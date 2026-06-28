"""Scan runner — launches tools/run-all.sh as a subprocess.

Security invariants:
- subprocess uses an argument list, never a shell string (shell=False)
- target_url is validated (scheme, host, SSRF) before invocation
- max_scan_minutes is enforced as a real subprocess timeout
- pinned IP from validation is threaded through to the script (A1)
- process group kill on timeout so grandchildren (ZAP docker) die too (B3)
- error_message is redacted and truncated before DB storage (A3)
- startup reconciliation marks orphaned 'running'/'queued' runs as 'failed' (B3)
- results are parsed and findings inserted after subprocess completes (C4)
"""

from __future__ import annotations

import json
import logging
import os
import re
import signal
import subprocess
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from .checks import (
    ALL_CHECK_IDS, CHECKS,
    get_not_testable_checks, get_partial_checks,
    get_sast_not_testable_checks, get_sast_partial_checks,
)
from .database import get_db
from .models import (
    ParsedFinding, RunStatus, RunSummary, ScanMode, ScanType, TargetType,
    SEVERITY_ORDER, compute_dedupe_hash, redact_secret,
)
from .parsers.base import OWASP_NAMES
from .scope import (
    ScopeConfig, SourcePathError, is_in_scope, parse_scope,
    validate_source_path,
)
from .target_validation import TargetValidationError, ValidationResult, validate_target

logger = logging.getLogger("masrek.scanner")

def _default_project_root() -> Path:
    """In local dev: backend/app/scanner.py → 3 parents → masrek/.
    In Docker: /app/app/scanner.py → 3 parents → / (wrong).
    MASREK_PROJECT_ROOT overrides for containers."""
    return Path(os.environ.get(
        "MASREK_PROJECT_ROOT",
        str(Path(__file__).resolve().parent.parent.parent),
    ))

_SCRIPT_PATH = _default_project_root() / "tools" / "run-all.sh"
_SAST_SCRIPT_PATH = _default_project_root() / "tools" / "run-sast.sh"
_RESULTS_BASE = Path(os.environ.get(
    "RESULTS_DIR",
    str(_default_project_root() / "results"),
))

_SAFE_HOST_RE = re.compile(r"[^a-zA-Z0-9._\-]")

_MAX_ERROR_MESSAGE_BYTES = 2048


def _safe_host(url: str) -> str:
    """Convert a URL's host:port into a filesystem-safe directory name."""
    parsed = urlparse(url)
    host = parsed.hostname or "unknown"
    port = parsed.port
    raw = f"{host}_{port}" if port else host
    sanitized = _SAFE_HOST_RE.sub("_", raw)
    sanitized = sanitized.lstrip(".")
    return sanitized or "unknown"


def resolve_mode(mode: ScanMode, target_url: str, scope: ScopeConfig) -> str:
    if mode == ScanMode.auto:
        return "active" if is_in_scope(target_url, scope) else "passive"
    return mode.value


class ScanRefusedError(Exception):
    pass


def reconcile_orphaned_runs(db_path: str | None = None) -> int:
    """Mark any run stuck in 'queued' or 'running' as 'failed' (orphaned by restart)."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db(db_path) as conn:
        cursor = conn.execute(
            "UPDATE runs SET status = ?, completed_at = ?, error_message = ? "
            "WHERE status IN (?, ?)",
            (
                RunStatus.failed.value, now,
                "Orphaned by server restart — was still running when the server stopped.",
                RunStatus.queued.value, RunStatus.running.value,
            ),
        )
        return cursor.rowcount


def start_scan(
    target_url: str,
    mode: ScanMode = ScanMode.auto,
    checks: list[str] | None = None,
    scan_type: ScanType = ScanType.baseline,
    scope: ScopeConfig | None = None,
    db_path: str | None = None,
) -> tuple[str, str]:
    """Validate, create a run record, and launch the scan in a background thread.

    Returns (run_id, resolved_mode). B4: single source for resolved mode.
    Raises ScanRefusedError or TargetValidationError.
    """
    if scope is None:
        scope = parse_scope()

    selected_checks = checks or ALL_CHECK_IDS

    validation = validate_target(target_url, scope)
    resolved = resolve_mode(mode, target_url, scope)

    if resolved == "active" and not is_in_scope(target_url, scope):
        raise ScanRefusedError(
            f"Active scanning of '{target_url}' is not authorized. "
            "Host is not in SCOPE.md allowlist. Only passive checks are available."
        )

    run_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    host = _safe_host(target_url)

    with get_db(db_path) as conn:
        conn.execute(
            "INSERT INTO runs (id, target_url, target_host, mode, status, created_at, "
            "selected_checks, scan_type) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (run_id, target_url, host, resolved, RunStatus.queued.value, now,
             ",".join(selected_checks), scan_type.value),
        )

    thread = threading.Thread(
        target=_run_scan,
        args=(run_id, target_url, resolved, scope, validation, selected_checks, scan_type, db_path),
        daemon=True,
    )
    thread.start()

    return run_id, resolved


def start_source_scan(
    source_path: str,
    checks: list[str] | None = None,
    scope: ScopeConfig | None = None,
    db_path: str | None = None,
) -> str:
    """Validate source path, create a run record, and launch SAST in background.

    Returns run_id. Raises SourcePathError if path is invalid.
    """
    if scope is None:
        scope = parse_scope()

    selected_checks = checks or ALL_CHECK_IDS
    resolved_path = validate_source_path(source_path, scope)

    source_name = _safe_host(f"source://{resolved_path.name}")
    run_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    with get_db(db_path) as conn:
        conn.execute(
            "INSERT INTO runs (id, target_url, target_host, mode, status, created_at, "
            "selected_checks, scan_type, target_type, source_path) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (run_id, f"source://{resolved_path}", source_name, "sast",
             RunStatus.queued.value, now,
             ",".join(selected_checks), "full", "source", str(resolved_path)),
        )

    thread = threading.Thread(
        target=_run_sast_scan,
        args=(run_id, resolved_path, selected_checks, scope, db_path),
        daemon=True,
    )
    thread.start()

    return run_id


def _run_sast_scan(
    run_id: str,
    source_path: Path,
    selected_checks: list[str],
    scope: ScopeConfig,
    db_path: str | None,
) -> None:
    """Execute tools/run-sast.sh as a subprocess."""
    timeout_seconds = scope.safety.max_scan_minutes * 60 * 2

    with get_db(db_path) as conn:
        conn.execute(
            "UPDATE runs SET status = ? WHERE id = ?",
            (RunStatus.running.value, run_id),
        )

    source_name = _safe_host(f"source://{source_path.name}")
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    results_dir = _RESULTS_BASE / source_name / ts / "sast"

    cmd = [
        "bash",
        str(_SAST_SCRIPT_PATH),
        "--source", str(source_path),
        "--checks", ",".join(selected_checks),
        "--results-dir", str(results_dir),
        "--max-minutes", str(scope.safety.max_scan_minutes),
    ]

    is_windows = os.name == "nt"
    popen_kwargs: dict = {}
    if not is_windows:
        popen_kwargs["start_new_session"] = True

    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            **popen_kwargs,
        )
        stdout, stderr = proc.communicate(timeout=timeout_seconds)
        returncode = proc.returncode
        status = RunStatus.done if returncode == 0 else RunStatus.failed
        error_msg = _sanitize_error(stderr) if returncode != 0 else None

    except subprocess.TimeoutExpired:
        if proc is not None:
            _kill_process_tree(proc, is_windows)
        status = RunStatus.timeout
        error_msg = f"SAST scan timed out after {scope.safety.max_scan_minutes} minutes"
        logger.warning("SAST run %s timed out", run_id)

    except Exception as exc:
        status = RunStatus.failed
        error_msg = _sanitize_error(str(exc))
        logger.exception("SAST run %s failed unexpectedly", run_id)

    # Parse SAST results
    summary_json = None
    if status in (RunStatus.done, RunStatus.timeout):
        try:
            if results_dir.exists():
                findings = _parse_sast_results(results_dir)

                selected_cats = {f"{cid}:2025" for cid in selected_checks}
                findings = [f for f in findings if f.category in selected_cats]

                findings.extend(_generate_sast_detectability_findings(
                    selected_checks, str(source_path),
                ))

                _insert_findings(run_id, findings, db_path)
                summary_json = _compute_summary(run_id, db_path)

                with get_db(db_path) as conn:
                    conn.execute(
                        "UPDATE runs SET results_dir = ? WHERE id = ?",
                        (str(results_dir.parent), run_id),
                    )
        except Exception as exc:
            logger.exception("Failed to parse SAST results for run %s", run_id)
            if not error_msg:
                error_msg = _sanitize_error(f"SAST result parsing failed: {exc}")

    now = datetime.now(timezone.utc).isoformat()
    with get_db(db_path) as conn:
        conn.execute(
            "UPDATE runs SET status = ?, completed_at = ?, error_message = ?, summary_json = ? "
            "WHERE id = ?",
            (status.value, now, error_msg, summary_json, run_id),
        )


def _run_scan(
    run_id: str,
    target_url: str,
    mode: str,
    scope: ScopeConfig,
    validation: ValidationResult,
    selected_checks: list[str],
    scan_type: ScanType,
    db_path: str | None,
) -> None:
    """Execute tools/run-all.sh in a subprocess with a real timeout."""
    per_tool_timeout = scope.safety.max_scan_minutes * 60
    if scan_type == ScanType.full:
        timeout_seconds = per_tool_timeout * 3
    else:
        timeout_seconds = per_tool_timeout * 2

    with get_db(db_path) as conn:
        conn.execute(
            "UPDATE runs SET status = ? WHERE id = ?",
            (RunStatus.running.value, run_id),
        )

    cmd = [
        "bash",
        str(_SCRIPT_PATH),
        "--target", target_url,
        "--mode", mode,
        "--checks", ",".join(selected_checks),
        "--scan-type", scan_type.value,
    ]
    # A1: pass pinned IP so the script connects to the validated address
    if validation.pinned_ip:
        cmd.extend(["--pinned-ip", validation.pinned_ip])

    is_windows = os.name == "nt"
    popen_kwargs: dict = {}
    if not is_windows:
        popen_kwargs["start_new_session"] = True

    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            **popen_kwargs,
        )
        stdout, stderr = proc.communicate(timeout=timeout_seconds)
        returncode = proc.returncode
        status = RunStatus.done if returncode == 0 else RunStatus.failed
        # A3: redact and truncate error output before storing
        error_msg = _sanitize_error(stderr) if returncode != 0 else None

    except subprocess.TimeoutExpired:
        # B3: kill the whole process group so grandchildren die too
        if proc is not None:
            _kill_process_tree(proc, is_windows)
        status = RunStatus.timeout
        error_msg = f"Scan timed out after {scope.safety.max_scan_minutes} minutes"
        logger.warning("Run %s timed out", run_id)
        stdout = ""

    except Exception as exc:
        status = RunStatus.failed
        error_msg = _sanitize_error(str(exc))
        logger.exception("Run %s failed unexpectedly", run_id)
        stdout = ""

    # C4: parse results, filter by selected checks, inject not-testable findings
    summary_json = None
    if status == RunStatus.done or status == RunStatus.timeout:
        try:
            results_dir = _find_results_dir(target_url)
            if results_dir:
                findings = _parse_all_results(results_dir, mode)

                selected_cats = {f"{cid}:2025" for cid in selected_checks}
                findings = [f for f in findings if f.category in selected_cats]

                findings.extend(_generate_detectability_findings(
                    selected_checks, target_url,
                ))

                _insert_findings(run_id, findings, db_path)
                summary_json = _compute_summary(run_id, db_path)

                with get_db(db_path) as conn:
                    conn.execute(
                        "UPDATE runs SET results_dir = ? WHERE id = ?",
                        (str(results_dir), run_id),
                    )
        except Exception as exc:
            logger.exception("Failed to parse results for run %s", run_id)
            if not error_msg:
                error_msg = _sanitize_error(f"Result parsing failed: {exc}")

    now = datetime.now(timezone.utc).isoformat()
    with get_db(db_path) as conn:
        conn.execute(
            "UPDATE runs SET status = ?, completed_at = ?, error_message = ?, summary_json = ? "
            "WHERE id = ?",
            (status.value, now, error_msg, summary_json, run_id),
        )


def _kill_process_tree(proc: subprocess.Popen, is_windows: bool) -> None:
    """Kill the process and its entire process group.

    Sends SIGTERM first to allow EXIT traps (e.g. defensive ZAP export) to fire,
    then SIGKILL after a grace period.
    """
    try:
        if is_windows:
            proc.kill()
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, OSError):
        pass
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            if not is_windows:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            else:
                proc.kill()
        except (ProcessLookupError, OSError):
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


def _sanitize_error(raw: str) -> str:
    """Redact secrets and truncate error messages before DB storage (A3)."""
    redacted = redact_secret(raw)
    if len(redacted) > _MAX_ERROR_MESSAGE_BYTES:
        redacted = redacted[:_MAX_ERROR_MESSAGE_BYTES] + "... [truncated]"
    return redacted


def _find_results_dir(target_url: str) -> Path | None:
    """Find the latest results directory for this target."""
    host_slug = _safe_host(target_url)
    host_dir = _RESULTS_BASE / host_slug
    if not host_dir.exists():
        return None
    # Find the most recent timestamped directory
    dirs = sorted(
        [d for d in host_dir.iterdir() if d.is_dir() and d.name != "latest"],
        key=lambda d: d.name,
        reverse=True,
    )
    return dirs[0] if dirs else None


def _parse_all_results(results_dir: Path, mode: str) -> list[ParsedFinding]:
    """Run all applicable parsers on the results directory."""
    from .parsers import (
        parse_headers, parse_zap, parse_nuclei,
        parse_nikto, parse_testssl, parse_gitleaks,
    )

    findings: list[ParsedFinding] = []
    passive_dir = results_dir / "passive"
    active_dir = results_dir / "active"

    # Passive parsers (always)
    findings.extend(parse_headers(passive_dir / "summary.json", ""))
    findings.extend(parse_testssl(passive_dir / "testssl.json", ""))

    # Active parsers (only if active mode)
    if mode == "active" and active_dir.exists():
        findings.extend(parse_zap(active_dir / "zap-report.json", ""))
        findings.extend(parse_nuclei(active_dir / "nuclei.jsonl", ""))
        findings.extend(parse_nikto(active_dir / "nikto.json", ""))

    # Static parsers (if available)
    findings.extend(parse_gitleaks(results_dir / "gitleaks.json", ""))

    return findings


def _insert_findings(
    run_id: str,
    findings: list[ParsedFinding],
    db_path: str | None,
) -> None:
    """Dedupe/merge findings and insert into the database.

    C3: On dedupe collision within a run, MERGE: union source_tool,
    keep highest severity, keep richest evidence/fix.
    """
    merged: dict[str, dict] = {}

    for f in findings:
        dhash = compute_dedupe_hash(f.category, f.location, f.title)

        if dhash in merged:
            existing = merged[dhash]
            # Union source_tool
            tools = set(existing["source_tool"].split(","))
            tools.add(f.source_tool)
            existing["source_tool"] = ",".join(sorted(tools))

            # Keep highest severity
            if SEVERITY_ORDER.get(f.severity, 4) < SEVERITY_ORDER.get(existing["severity"], 4):
                existing["severity"] = f.severity

            # Keep richest evidence
            if len(f.evidence or "") > len(existing.get("evidence") or ""):
                existing["evidence"] = f.evidence

            # Keep richest fix
            if len(f.fix or "") > len(existing.get("fix") or ""):
                existing["fix"] = f.fix

            # Upgrade verified status (yes > needs-manual > no)
            _VERIFIED_ORDER = {"yes": 0, "needs-manual": 1, "no": 2}
            if _VERIFIED_ORDER.get(f.verified, 2) < _VERIFIED_ORDER.get(existing["verified"], 2):
                existing["verified"] = f.verified
            # Upgrade mapping precision (exact > tag > fallback)
            _MAPPING_ORDER = {"exact": 0, "tag": 1, "fallback": 2}
            if _MAPPING_ORDER.get(f.mapping, 2) < _MAPPING_ORDER.get(existing.get("mapping", "fallback"), 2):
                existing["mapping"] = f.mapping
        else:
            merged[dhash] = {
                "id": str(uuid.uuid4()),
                "run_id": run_id,
                "severity": f.severity,
                "title": f.title,
                "category": f.category,
                "category_name": f.category_name,
                "location": f.location,
                "evidence": f.evidence,
                "verified": f.verified,
                "fix": f.fix,
                "source_tool": f.source_tool,
                "dedupe_hash": dhash,
                "mapping": f.mapping,
            }

    with get_db(db_path) as conn:
        for row in merged.values():
            conn.execute(
                "INSERT OR REPLACE INTO findings "
                "(id, run_id, severity, title, category, category_name, "
                "location, evidence, verified, fix, source_tool, dedupe_hash, mapping) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    row["id"], row["run_id"], row["severity"], row["title"],
                    row["category"], row["category_name"], row["location"],
                    row["evidence"], row["verified"], row["fix"],
                    row["source_tool"], row["dedupe_hash"], row["mapping"],
                ),
            )


def _generate_detectability_findings(
    selected_checks: list[str],
    target_url: str,
) -> list[ParsedFinding]:
    """Inject informational findings for checks that DAST cannot (fully) test."""
    findings: list[ParsedFinding] = []

    for check in get_not_testable_checks(selected_checks):
        cat = f"{check.id}:2025"
        findings.append(ParsedFinding(
            severity="info",
            title=f"{check.id}: {check.name} — לא ניתן לבדיקה באמצעות DAST",
            category=cat,
            category_name=OWASP_NAMES.get(cat, check.name),
            location=target_url,
            evidence=check.reason,
            verified="no",
            fix=f"Use SAST/SCA tools to test {check.id} ({check.name}).",
            source_tool="masrek-check-registry",
        ))

    for check in get_partial_checks(selected_checks):
        cat = f"{check.id}:2025"
        findings.append(ParsedFinding(
            severity="info",
            title=f"{check.id}: {check.name} — כיסוי חלקי בלבד",
            category=cat,
            category_name=OWASP_NAMES.get(cat, check.name),
            location=target_url,
            evidence=check.reason,
            verified="no",
            fix=f"DAST provides partial coverage for {check.id}. "
                f"Complement with manual review or SAST.",
            source_tool="masrek-check-registry",
        ))

    return findings


def _parse_sast_results(results_dir: Path) -> list[ParsedFinding]:
    """Run SAST parsers on the results directory."""
    from .parsers import parse_gitleaks, parse_osv, parse_semgrep, parse_trivy

    findings: list[ParsedFinding] = []
    findings.extend(parse_osv(results_dir / "osv-scanner.json", ""))
    findings.extend(parse_trivy(results_dir / "trivy.json", ""))
    findings.extend(parse_semgrep(results_dir / "semgrep.json", ""))
    findings.extend(parse_gitleaks(results_dir / "gitleaks.json", ""))
    return findings


def _generate_sast_detectability_findings(
    selected_checks: list[str],
    source_path: str,
) -> list[ParsedFinding]:
    """Inject informational findings for checks that SAST cannot test."""
    findings: list[ParsedFinding] = []

    for check in get_sast_not_testable_checks(selected_checks):
        cat = f"{check.id}:2025"
        findings.append(ParsedFinding(
            severity="info",
            title=f"{check.id}: {check.name} — לא ניתן לבדיקה באמצעות SAST",
            category=cat,
            category_name=OWASP_NAMES.get(cat, check.name),
            location=source_path,
            evidence=f"SAST/SCA cannot test {check.id}. {check.reason}",
            verified="no",
            fix=f"Use DAST tools to test {check.id} ({check.name}).",
            source_tool="masrek-check-registry",
        ))

    for check in get_sast_partial_checks(selected_checks):
        cat = f"{check.id}:2025"
        findings.append(ParsedFinding(
            severity="info",
            title=f"{check.id}: {check.name} — כיסוי חלקי ב-SAST",
            category=cat,
            category_name=OWASP_NAMES.get(cat, check.name),
            location=source_path,
            evidence=check.sast_reason or check.reason,
            verified="no",
            fix=f"SAST provides partial coverage for {check.id}. "
                f"Complement with DAST and manual review.",
            source_tool="masrek-check-registry",
        ))

    return findings


def _compute_summary(run_id: str, db_path: str | None) -> str:
    """Compute severity counts for a run and return as JSON string."""
    with get_db(db_path) as conn:
        rows = conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM findings "
            "WHERE run_id = ? GROUP BY severity",
            (run_id,),
        ).fetchall()

    counts = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for row in rows:
        sev = row["severity"]
        cnt = row["cnt"]
        if sev in counts:
            counts[sev] = cnt
        counts["total"] += cnt

    return json.dumps(counts)

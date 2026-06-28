"""Parser for semgrep JSON output → multi-category OWASP findings.

semgrep results carry CWE and OWASP metadata per rule. We map:
  - CWE/OWASP → A05 (injection), A07 (hardcoded creds), A09 (logging),
    A06 (insecure design patterns), A02 (misconfig in code).
  - Secret values in findings are redacted — only type + location kept.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ..models import ParsedFinding
from .base import CWE_TO_OWASP, OWASP_NAMES, parse_cwe_id, safe_load_json

logger = logging.getLogger("masrek.parsers.semgrep")

_SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}

_SECRET_VALUE_RE = re.compile(
    r'(password|secret|token|key|credential|api.?key|passwd)\s*[:=]\s*\S+',
    re.IGNORECASE,
)

_SEMGREP_OWASP_RE = re.compile(r'A0?(\d{1,2})', re.IGNORECASE)


def _map_severity(semgrep_sev: str) -> str:
    return _SEVERITY_MAP.get(semgrep_sev.upper(), "medium")


def _redact_secrets(text: str) -> str:
    return _SECRET_VALUE_RE.sub(r'\1=***REDACTED***', text)


def _extract_owasp_from_metadata(metadata: dict) -> str | None:
    """Try to extract OWASP category from semgrep rule metadata."""
    owasp = metadata.get("owasp") or []
    if isinstance(owasp, str):
        owasp = [owasp]
    for entry in owasp:
        m = _SEMGREP_OWASP_RE.search(str(entry))
        if m:
            num = int(m.group(1))
            if 1 <= num <= 10:
                cat = f"A{num:02d}:2025"
                if cat in OWASP_NAMES:
                    return cat
    return None


def _map_category(metadata: dict) -> tuple[str, str, str]:
    """Map semgrep finding to OWASP category via CWE or OWASP metadata.

    Priority: CWE mapping (exact) > OWASP metadata > fallback to A02.
    """
    cwe_list = metadata.get("cwe") or []
    if isinstance(cwe_list, str):
        cwe_list = [cwe_list]

    for cwe_str in cwe_list:
        cwe_id = parse_cwe_id(cwe_str)
        if cwe_id and cwe_id in CWE_TO_OWASP:
            cat = CWE_TO_OWASP[cwe_id]
            return cat, OWASP_NAMES[cat], "exact"

    owasp_cat = _extract_owasp_from_metadata(metadata)
    if owasp_cat:
        return owasp_cat, OWASP_NAMES[owasp_cat], "tag"

    return "A02:2025", OWASP_NAMES["A02:2025"], "fallback"


def _parse_result(result: dict) -> ParsedFinding:
    """Parse a single semgrep result into a ParsedFinding."""
    check_id = result.get("check_id", "unknown")
    path = result.get("path", "unknown")
    start = result.get("start", {})
    line = start.get("line", "?")
    end = result.get("end", {})
    end_line = end.get("line", line)

    extra = result.get("extra", {})
    severity = _map_severity(extra.get("severity", "WARNING"))
    message = extra.get("message", "")
    if len(message) > 300:
        message = message[:297] + "..."
    metadata = extra.get("metadata", {})

    category, category_name, mapping = _map_category(metadata)

    rule_short = check_id.rsplit(".", 1)[-1] if "." in check_id else check_id
    title = f"{rule_short}: {message[:100]}" if message else rule_short
    if len(title) > 200:
        title = title[:197] + "..."

    location = f"{path}:{line}"

    evidence_parts = [f"Rule: {check_id}"]
    if message:
        evidence_parts.append(message)

    cwe_list = metadata.get("cwe") or []
    if isinstance(cwe_list, str):
        cwe_list = [cwe_list]
    if cwe_list:
        evidence_parts.append(f"CWE: {', '.join(str(c) for c in cwe_list[:5])}")

    matched_code = extra.get("lines", "")
    if matched_code:
        if len(matched_code) > 200:
            matched_code = matched_code[:197] + "..."
        evidence_parts.append(f"Code: {matched_code}")

    fix = extra.get("fix", metadata.get("fix", ""))
    if not fix:
        refs = metadata.get("references") or []
        if refs:
            fix = f"See: {refs[0]}"

    return ParsedFinding(
        severity=severity,
        title=_redact_secrets(title),
        category=category,
        category_name=category_name,
        location=location,
        evidence=_redact_secrets("\n".join(evidence_parts)),
        verified="yes",
        fix=_redact_secrets(str(fix)) if fix else "",
        source_tool="semgrep",
        mapping=mapping,
    )


def parse(file_path: Path, run_id: str) -> list[ParsedFinding]:
    """Parse semgrep JSON output into ParsedFinding objects."""
    data = safe_load_json(file_path)
    if data is None:
        return []

    findings: list[ParsedFinding] = []

    results = data.get("results", [])
    for result in results:
        findings.append(_parse_result(result))

    errors = data.get("errors", [])
    if errors:
        logger.warning("semgrep reported %d errors", len(errors))

    logger.info("semgrep parser: %d findings from %s", len(findings), file_path)
    return findings

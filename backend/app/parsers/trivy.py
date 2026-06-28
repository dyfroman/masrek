"""Parser for trivy JSON output → A03:2025 + A08:2025 findings.

trivy reports:
  - Dependency vulnerabilities (type=library) → A03:2025 (Supply Chain)
  - IaC/config misconfigurations (type=misconfig/secret) → A08:2025 (Integrity)

Severity is taken directly from trivy's severity field (CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN).
Secret VALUES are redacted — only the type/location is kept.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ..models import ParsedFinding
from .base import OWASP_NAMES, safe_load_json

logger = logging.getLogger("masrek.parsers.trivy")

_A03 = "A03:2025"
_A08 = "A08:2025"
_A03_NAME = OWASP_NAMES[_A03]
_A08_NAME = OWASP_NAMES[_A08]

_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}

_SECRET_VALUE_RE = re.compile(
    r'(password|secret|token|key|credential|api.?key)\s*[:=]\s*\S+',
    re.IGNORECASE,
)


def _map_severity(trivy_sev: str) -> str:
    return _SEVERITY_MAP.get(trivy_sev.upper(), "info")


def _redact_secrets(text: str) -> str:
    return _SECRET_VALUE_RE.sub(r'\1=***REDACTED***', text)


def _parse_vulnerability(vuln: dict, target: str, target_type: str) -> ParsedFinding:
    """Parse a single trivy vulnerability (dependency CVE) into an A03 finding."""
    vuln_id = vuln.get("VulnerabilityID", "UNKNOWN")
    pkg_name = vuln.get("PkgName", "unknown")
    installed = vuln.get("InstalledVersion", "?")
    fixed = vuln.get("FixedVersion", "")
    severity = _map_severity(vuln.get("Severity", "UNKNOWN"))
    title_text = vuln.get("Title", vuln.get("Description", ""))
    if len(title_text) > 200:
        title_text = title_text[:197] + "..."

    location = f"{pkg_name}@{installed} ({target})"

    evidence_parts = [f"ID: {vuln_id}"]
    if title_text:
        evidence_parts.append(title_text)
    refs = vuln.get("References", [])
    if refs:
        evidence_parts.append(f"Refs: {refs[0]}")

    fix_text = ""
    if fixed:
        fix_text = f"Upgrade {pkg_name} to {fixed}."

    return ParsedFinding(
        severity=severity,
        title=f"{vuln_id}: {pkg_name} ({target_type})",
        category=_A03,
        category_name=_A03_NAME,
        location=location,
        evidence=_redact_secrets("\n".join(evidence_parts)),
        verified="yes",
        fix=fix_text,
        source_tool="trivy",
        mapping="exact",
    )


def _parse_misconfig(mc: dict, target: str) -> ParsedFinding:
    """Parse a single trivy misconfiguration into an A08 finding."""
    mc_id = mc.get("ID", mc.get("AVDID", "UNKNOWN"))
    mc_type = mc.get("Type", "config")
    title = mc.get("Title", mc.get("Message", "Misconfiguration"))
    if len(title) > 200:
        title = title[:197] + "..."
    severity = _map_severity(mc.get("Severity", "UNKNOWN"))
    desc = mc.get("Description", "")
    if len(desc) > 500:
        desc = desc[:497] + "..."
    resolution = mc.get("Resolution", "")

    location = f"{target}:{mc.get('CauseMetadata', {}).get('StartLine', '?')}"

    evidence_parts = [f"ID: {mc_id}", f"Type: {mc_type}"]
    if desc:
        evidence_parts.append(desc)

    return ParsedFinding(
        severity=severity,
        title=f"{mc_id}: {title}",
        category=_A08,
        category_name=_A08_NAME,
        location=location,
        evidence=_redact_secrets("\n".join(evidence_parts)),
        verified="yes",
        fix=_redact_secrets(resolution),
        source_tool="trivy",
        mapping="exact",
    )


def parse(file_path: Path, run_id: str) -> list[ParsedFinding]:
    """Parse trivy JSON output into ParsedFinding objects."""
    data = safe_load_json(file_path)
    if data is None:
        return []

    findings: list[ParsedFinding] = []

    results = data.get("Results", [])
    for result in results:
        target = result.get("Target", "unknown")
        target_type = result.get("Type", "")

        for vuln in result.get("Vulnerabilities", []):
            findings.append(_parse_vulnerability(vuln, target, target_type))

        for mc in result.get("Misconfigurations", []):
            findings.append(_parse_misconfig(mc, target))

    logger.info("trivy parser: %d findings from %s", len(findings), file_path)
    return findings

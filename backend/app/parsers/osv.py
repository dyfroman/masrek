"""Parser for osv-scanner JSON output → A03:2025 findings.

osv-scanner reports known CVEs in project dependencies by scanning lockfiles.
Each vulnerability maps to A03:2025 (Software Supply Chain Failures).

Severity mapping from CVSS score (osv-scanner provides database_specific.severity):
  critical ≥ 9.0, high ≥ 7.0, medium ≥ 4.0, low ≥ 0.1, info = 0 or missing.
"""

from __future__ import annotations

import logging
from pathlib import Path

from ..models import ParsedFinding
from .base import OWASP_NAMES, safe_load_json

logger = logging.getLogger("masrek.parsers.osv")

_CATEGORY = "A03:2025"
_CATEGORY_NAME = OWASP_NAMES[_CATEGORY]


def _cvss_to_severity(score: float | None) -> str:
    if score is None or score <= 0:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _extract_cvss(vuln: dict) -> float | None:
    """Extract the highest CVSS score from a vulnerability entry."""
    best = None
    for sev in vuln.get("severity", []):
        score = sev.get("score")
        if isinstance(score, str):
            # CVSS vector string — extract base score from the end
            # e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" → parse via last metric
            # osv-scanner sometimes provides a numeric score directly
            try:
                score = float(score)
            except ValueError:
                continue
        if isinstance(score, (int, float)) and (best is None or score > best):
            best = score

    # Fallback: check database_specific severity text
    if best is None:
        db_sev = vuln.get("database_specific", {}).get("severity")
        if isinstance(db_sev, str):
            _TEXT_MAP = {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.0, "MEDIUM": 5.0, "LOW": 2.5}
            best = _TEXT_MAP.get(db_sev.upper())

    return best


def _extract_ids(vuln: dict) -> tuple[str, str]:
    """Return (primary_id, all_aliases_str) from a vulnerability."""
    vid = vuln.get("id", "UNKNOWN")
    aliases = vuln.get("aliases", [])
    # Prefer a CVE alias as the primary display ID
    cve_aliases = [a for a in aliases if a.startswith("CVE-")]
    primary = cve_aliases[0] if cve_aliases else vid
    all_ids = sorted(set([vid] + aliases))
    return primary, ", ".join(all_ids)


def parse(file_path: Path, run_id: str) -> list[ParsedFinding]:
    """Parse osv-scanner JSON output into ParsedFinding objects."""
    data = safe_load_json(file_path)
    if data is None:
        return []

    findings: list[ParsedFinding] = []

    results = data.get("results", [])
    for result in results:
        source_path = result.get("source", {}).get("path", "unknown")
        source_type = result.get("source", {}).get("type", "")

        for pkg_info in result.get("packages", []):
            pkg = pkg_info.get("package", {})
            pkg_name = pkg.get("name", "unknown")
            pkg_version = pkg.get("version", "unknown")
            pkg_ecosystem = pkg.get("ecosystem", "")
            location = f"{pkg_name}@{pkg_version} ({source_path})"

            for vuln in pkg_info.get("vulnerabilities", []):
                primary_id, all_ids = _extract_ids(vuln)
                summary = vuln.get("summary", vuln.get("details", ""))
                if len(summary) > 500:
                    summary = summary[:497] + "..."
                cvss = _extract_cvss(vuln)
                severity = _cvss_to_severity(cvss)

                # Build fix advice from affected[].ranges[].events
                fix_versions = []
                for affected in vuln.get("affected", []):
                    for rng in affected.get("ranges", []):
                        for event in rng.get("events", []):
                            if "fixed" in event:
                                fix_versions.append(event["fixed"])
                fix = ""
                if fix_versions:
                    fix = f"Upgrade {pkg_name} to {' or '.join(sorted(set(fix_versions)))}."

                findings.append(ParsedFinding(
                    severity=severity,
                    title=f"{primary_id}: {pkg_name} ({pkg_ecosystem})",
                    category=_CATEGORY,
                    category_name=_CATEGORY_NAME,
                    location=location,
                    evidence=f"IDs: {all_ids}\n{summary}",
                    verified="yes",
                    fix=fix,
                    source_tool="osv-scanner",
                    mapping="exact",
                ))

    logger.info("osv-scanner parser: %d findings from %s", len(findings), file_path)
    return findings

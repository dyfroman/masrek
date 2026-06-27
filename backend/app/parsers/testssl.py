"""Parser for testssl.sh JSON output (testssl.json) -> mostly A04.

testssl severity mapping:
  CRITICAL -> critical, HIGH -> high, MEDIUM -> medium,
  LOW -> low, INFO/OK/WARN -> info
"""

from __future__ import annotations

from pathlib import Path

from ..models import ParsedFinding, redact_secret
from .base import safe_load_json

_TESTSSL_SEVERITY = {
    "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
    "LOW": "low", "INFO": "info", "OK": "info", "WARN": "low",
}


def parse(file_path: Path, run_id: str) -> list[ParsedFinding]:
    data = safe_load_json(file_path)
    if not data:
        return []

    # testssl JSON is a list of finding objects
    if not isinstance(data, list):
        data = data.get("scanResult", []) if isinstance(data, dict) else []

    findings: list[ParsedFinding] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        sev_raw = item.get("severity", "INFO").upper()
        if sev_raw in ("OK", "INFO"):
            continue  # skip purely informational "everything fine" entries

        severity = _TESTSSL_SEVERITY.get(sev_raw, "info")
        finding_text = item.get("finding", "")
        test_id = item.get("id", "")

        findings.append(ParsedFinding(
            severity=severity,
            title=f"TLS: {test_id}" if test_id else "TLS issue",
            category="A04:2025",
            category_name="Cryptographic Failures",
            location=item.get("ip", ""),
            evidence=redact_secret(finding_text[:500]),
            verified="yes",
            fix="Update TLS configuration per Mozilla SSL Configuration Generator.",
            source_tool="testssl",
        ))

    return findings

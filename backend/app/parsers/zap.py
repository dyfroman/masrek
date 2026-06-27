"""Parser for ZAP JSON report (zap-report.json).

ZAP severity mapping (riskcode):
  3 -> high, 2 -> medium, 1 -> low, 0 -> info
ZAP confidence mapping (used for verified status):
  3 (High) -> yes, 2 (Medium) -> needs-manual, 1/0 -> no
"""

from __future__ import annotations

from pathlib import Path

from ..models import ParsedFinding, normalize_location, redact_secret
from .base import safe_load_json, cwe_to_owasp

_ZAP_SEVERITY = {3: "high", 2: "medium", 1: "low", 0: "info"}
_ZAP_VERIFIED = {3: "yes", 2: "needs-manual", 1: "no", 0: "no"}


_ZAP_RISK_NAME = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0}


def parse(file_path: Path, run_id: str) -> list[ParsedFinding]:
    data = safe_load_json(file_path)
    if not data:
        return []

    findings: list[ParsedFinding] = []

    # Traditional report format: site > alerts (from jsonreport endpoint or file)
    if "site" in data:
        for site in data.get("site", []):
            for alert in site.get("alerts", []):
                findings.append(_parse_report_alert(alert))
    # API alerts format: {"alerts": [...]} (from /JSON/core/view/alerts/)
    elif "alerts" in data:
        for alert in data.get("alerts", []):
            findings.append(_parse_api_alert(alert))

    return findings


def _parse_cwe(alert: dict) -> tuple[int | None, str]:
    """Extract cweid and return (cwe_id, mapping). Filters out invalid values like -1 and 0."""
    try:
        raw = int(alert.get("cweid", 0))
        if raw > 0:
            return raw, "exact"
    except (ValueError, TypeError):
        pass
    return None, "fallback"


def _parse_report_alert(alert: dict) -> ParsedFinding:
    cwe_id, _ = _parse_cwe(alert)
    category, category_name, mapping = cwe_to_owasp(cwe_id)
    riskcode = int(alert.get("riskcode", 0))
    confidence = int(alert.get("confidence", 0))

    instances = alert.get("instances", [])
    location = instances[0].get("uri", "") if instances else ""
    location = normalize_location(location)

    evidence_parts = []
    if alert.get("desc"):
        evidence_parts.append(alert["desc"][:200])
    if instances:
        inst = instances[0]
        if inst.get("evidence"):
            evidence_parts.append(f"Evidence: {inst['evidence'][:200]}")

    return ParsedFinding(
        severity=_ZAP_SEVERITY.get(riskcode, "info"),
        title=alert.get("name", "Unknown ZAP alert"),
        category=category,
        category_name=category_name,
        location=location,
        evidence=redact_secret(" | ".join(evidence_parts)),
        verified=_ZAP_VERIFIED.get(confidence, "no"),
        fix=alert.get("solution", ""),
        source_tool="zap",
        mapping=mapping,
    )


def _parse_api_alert(alert: dict) -> ParsedFinding:
    """Parse an alert from the ZAP REST API format (/JSON/core/view/alerts/)."""
    cwe_id, _ = _parse_cwe(alert)
    category, category_name, mapping = cwe_to_owasp(cwe_id)
    riskcode = _ZAP_RISK_NAME.get(alert.get("risk", ""), 0)
    confidence_str = alert.get("confidence", "Low")
    confidence = _ZAP_RISK_NAME.get(confidence_str, 0)

    location = normalize_location(alert.get("url", ""))

    evidence_parts = []
    if alert.get("description"):
        evidence_parts.append(alert["description"][:200])
    if alert.get("evidence"):
        evidence_parts.append(f"Evidence: {alert['evidence'][:200]}")

    return ParsedFinding(
        severity=_ZAP_SEVERITY.get(riskcode, "info"),
        title=alert.get("name", alert.get("alert", "Unknown ZAP alert")),
        category=category,
        category_name=category_name,
        location=location,
        evidence=redact_secret(" | ".join(evidence_parts)),
        verified=_ZAP_VERIFIED.get(confidence, "no"),
        fix=alert.get("solution", ""),
        source_tool="zap",
        mapping=mapping,
    )

"""Parser for nuclei JSONL output (nuclei.jsonl).

Nuclei severity mapping (direct string match):
  critical -> critical, high -> high, medium -> medium,
  low -> low, info/unknown -> info
"""

from __future__ import annotations

from pathlib import Path

from ..models import ParsedFinding, normalize_location, redact_secret
from .base import safe_load_jsonl, parse_cwe_id, cwe_to_owasp, tags_to_owasp

_NUCLEI_SEVERITY = {
    "critical": "critical", "high": "high", "medium": "medium",
    "low": "low", "info": "info", "unknown": "info",
}


def parse(file_path: Path, run_id: str) -> list[ParsedFinding]:
    records = safe_load_jsonl(file_path)
    if not records:
        return []

    findings: list[ParsedFinding] = []
    for rec in records:
        info = rec.get("info", {})
        severity = _NUCLEI_SEVERITY.get(
            info.get("severity", "info").lower(), "info"
        )

        cwe_ids = info.get("classification", {}).get("cwe-id", [])
        cwe_id = None
        if cwe_ids:
            cwe_id = parse_cwe_id(cwe_ids[0])

        category, category_name, mapping = cwe_to_owasp(cwe_id)

        if mapping == "fallback":
            tags = info.get("tags", [])
            tag_result = tags_to_owasp(tags)
            if tag_result:
                category, category_name, mapping = tag_result

        matched = rec.get("matched-at", rec.get("host", ""))
        location = normalize_location(matched)

        evidence_parts = []
        if rec.get("extracted-results"):
            evidence_parts.append(str(rec["extracted-results"])[:200])
        if rec.get("matcher-name"):
            evidence_parts.append(f"matcher: {rec['matcher-name']}")
        if rec.get("curl-command"):
            evidence_parts.append(f"curl: {rec['curl-command'][:100]}")

        remediation = info.get("remediation", "")
        if not remediation and info.get("reference"):
            refs = info["reference"]
            if isinstance(refs, list):
                remediation = f"See: {refs[0]}" if refs else ""

        findings.append(ParsedFinding(
            severity=severity,
            title=info.get("name", rec.get("template-id", "Unknown nuclei finding")),
            category=category,
            category_name=category_name,
            location=location,
            evidence=redact_secret(" | ".join(evidence_parts)) if evidence_parts else "",
            verified="yes" if severity in ("critical", "high") else "needs-manual",
            fix=remediation,
            source_tool="nuclei",
            mapping=mapping,
        ))

    return findings

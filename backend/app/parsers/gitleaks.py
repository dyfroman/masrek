"""Parser for gitleaks JSON output.

R6: NEVER persist the raw secret value. Store only
"secret detected at <file:line>" + a redacted/masked token.
Redaction happens HERE, at parse time, before findings touch the DB.
"""

from __future__ import annotations

from pathlib import Path

from ..models import ParsedFinding, redact_gitleaks_finding
from .base import safe_load_json


def parse(file_path: Path, run_id: str) -> list[ParsedFinding]:
    data = safe_load_json(file_path)
    if not data:
        return []

    if not isinstance(data, list):
        return []

    findings: list[ParsedFinding] = []
    for item in data:
        if not isinstance(item, dict):
            continue

        rule_id = item.get("RuleID", item.get("ruleID", "unknown"))
        file_loc = item.get("File", item.get("file", "unknown"))
        line = item.get("StartLine", item.get("startLine", 0))
        raw_match = item.get("Match", item.get("match", ""))
        description = item.get("Description", item.get("description", ""))

        # R6: redact the secret before it ever touches the DB
        evidence = redact_gitleaks_finding(raw_match, file_loc, line)

        findings.append(ParsedFinding(
            severity="high",
            title=f"Secret detected: {rule_id}",
            category="A02:2025",
            category_name="Security Misconfiguration",
            location=f"{file_loc}:{line}",
            evidence=evidence,
            verified="yes",
            fix=f"Rotate the exposed secret ({rule_id}), remove it from source, "
                f"and use environment variables or a secrets manager instead.",
            source_tool="gitleaks",
        ))

    return findings

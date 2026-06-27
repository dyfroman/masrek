"""Parser for nikto JSON output (nikto.json).

Nikto doesn't provide severity levels directly. We map OSVDB/message patterns:
  - Anything mentioning injection/XSS/RCE -> high (A05)
  - Missing headers / info disclosure -> low (A02)
  - Default/known files -> medium (A02)
  - Everything else -> low (A02)
"""

from __future__ import annotations

import re
from pathlib import Path

from ..models import ParsedFinding, normalize_location, redact_secret
from .base import safe_load_json

_HIGH_PATTERNS = re.compile(
    r"(injection|xss|cross.site|rce|remote.code|command.exec|sql.inject)",
    re.IGNORECASE,
)
_MEDIUM_PATTERNS = re.compile(
    r"(default|backup|\.bak|\.old|\.orig|admin|phpinfo|server-status|\.git)",
    re.IGNORECASE,
)


def _classify(msg: str) -> tuple[str, str, str]:
    """Return (severity, owasp_category, category_name) based on message text."""
    if _HIGH_PATTERNS.search(msg):
        return "high", "A05:2025", "Injection"
    if _MEDIUM_PATTERNS.search(msg):
        return "medium", "A02:2025", "Security Misconfiguration"
    return "low", "A02:2025", "Security Misconfiguration"


def parse(file_path: Path, run_id: str) -> list[ParsedFinding]:
    data = safe_load_json(file_path)
    if not data:
        return []

    findings: list[ParsedFinding] = []

    # Nikto JSON can be a dict with "vulnerabilities" or a list
    vulns = []
    if isinstance(data, dict):
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            # Some nikto versions nest under host->entries
            for host_data in data.get("host", []) if isinstance(data.get("host"), list) else [data.get("host", {})]:
                if isinstance(host_data, dict):
                    vulns.extend(host_data.get("items", []))
    elif isinstance(data, list):
        vulns = data

    for vuln in vulns:
        if not isinstance(vuln, dict):
            continue
        msg = vuln.get("msg", vuln.get("description", ""))
        url = vuln.get("url", vuln.get("uri", ""))
        severity, category, category_name = _classify(msg)
        location = normalize_location(url) if url else ""

        findings.append(ParsedFinding(
            severity=severity,
            title=msg[:120] if msg else "Nikto finding",
            category=category,
            category_name=category_name,
            location=location,
            evidence=redact_secret(msg[:500]),
            verified="needs-manual",
            fix="Review and remediate the reported issue.",
            source_tool="nikto",
        ))

    return findings

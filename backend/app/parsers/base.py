"""Shared utilities for parsers: safe JSON loading, CWE-to-OWASP mapping."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger("masrek.parsers")


def safe_load_json(path: Path) -> Any | None:
    """Load JSON from *path*. Returns None if the file is missing, empty, or invalid."""
    if not path.exists():
        return None
    try:
        text = path.read_text(encoding="utf-8").strip()
        if not text:
            return None
        return json.loads(text)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return None


def safe_load_jsonl(path: Path) -> list[dict]:
    """Load a JSONL file (one JSON object per line). Returns [] on error."""
    if not path.exists():
        return []
    results = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError as exc:
        logger.warning("Failed to read %s: %s", path, exc)
    return results


# CWE -> OWASP Top 10:2025 mapping (single source of truth).
CWE_TO_OWASP: dict[int, str] = {
    # A01: Broken Access Control
    22: "A01:2025", 23: "A01:2025", 35: "A01:2025",
    200: "A01:2025", 264: "A01:2025", 284: "A01:2025", 285: "A01:2025",
    352: "A01:2025", 639: "A01:2025", 862: "A01:2025",
    863: "A01:2025", 918: "A01:2025",
    # A02: Security Misconfiguration
    2: "A02:2025", 16: "A02:2025",
    215: "A02:2025", 497: "A02:2025", 548: "A02:2025",
    611: "A02:2025", 693: "A02:2025",
    # A03: Software Supply Chain Failures
    829: "A03:2025", 1035: "A03:2025", 1104: "A03:2025",
    # A04: Cryptographic Failures
    261: "A04:2025", 296: "A04:2025", 310: "A04:2025",
    319: "A04:2025", 326: "A04:2025", 327: "A04:2025",
    328: "A04:2025", 330: "A04:2025", 331: "A04:2025",
    614: "A04:2025",
    # A05: Injection
    20: "A05:2025", 77: "A05:2025", 78: "A05:2025",
    79: "A05:2025", 89: "A05:2025", 90: "A05:2025",
    91: "A05:2025", 94: "A05:2025", 95: "A05:2025", 917: "A05:2025",
    # A06: Insecure Design
    73: "A06:2025", 183: "A06:2025", 501: "A06:2025",
    # A07: Authentication Failures
    256: "A07:2025", 287: "A07:2025", 306: "A07:2025",
    307: "A07:2025", 384: "A07:2025", 521: "A07:2025",
    522: "A07:2025", 613: "A07:2025", 640: "A07:2025",
    798: "A07:2025",
    # A08: Software and Data Integrity Failures
    345: "A08:2025", 353: "A08:2025", 426: "A08:2025",
    494: "A08:2025", 502: "A08:2025", 565: "A08:2025",
    # A09: Security Logging & Alerting Failures
    117: "A09:2025", 223: "A09:2025", 532: "A09:2025",
    # A10: Mishandling of Exceptional Conditions
    209: "A10:2025", 248: "A10:2025", 754: "A10:2025",
    755: "A10:2025",
}

OWASP_NAMES: dict[str, str] = {
    "A01:2025": "Broken Access Control",
    "A02:2025": "Security Misconfiguration",
    "A03:2025": "Software Supply Chain Failures",
    "A04:2025": "Cryptographic Failures",
    "A05:2025": "Injection",
    "A06:2025": "Insecure Design",
    "A07:2025": "Authentication Failures",
    "A08:2025": "Software and Data Integrity Failures",
    "A09:2025": "Security Logging & Alerting Failures",
    "A10:2025": "Mishandling of Exceptional Conditions",
}

# Tag → OWASP category for nuclei findings without a usable CWE.
# First match wins; order matters (more specific tags first).
TAG_TO_OWASP: list[tuple[set[str], str]] = [
    ({"xss"},                          "A05:2025"),
    ({"sqli", "sql-injection"},        "A05:2025"),
    ({"injection", "rce", "ssti", "xxe", "lfi", "rfi", "command-injection"}, "A05:2025"),
    ({"ssrf", "idor", "traversal"},    "A01:2025"),
    ({"exposure"},                     "A01:2025"),
    ({"default-login", "default-credential"}, "A07:2025"),
    ({"auth", "login", "brute-force"}, "A07:2025"),
    ({"misconfig", "config"},          "A02:2025"),
    ({"cve"},                          "A02:2025"),
]

_CWE_RE = re.compile(r"(?:CWE-)?(\d+)", re.IGNORECASE)


def parse_cwe_id(raw: str | int | None) -> int | None:
    """Extract numeric CWE from various formats: 'CWE-79', 'cwe-79', 79, 'cwe-200'."""
    if raw is None:
        return None
    if isinstance(raw, int):
        return raw if raw > 0 else None
    m = _CWE_RE.search(str(raw))
    return int(m.group(1)) if m else None


def cwe_to_owasp(cwe_id: int | None) -> tuple[str, str, str]:
    """Map a CWE ID to (owasp_category, category_name, mapping).

    mapping is "exact" when CWE is in the table, "fallback" when it's not.
    """
    if cwe_id and cwe_id in CWE_TO_OWASP:
        cat = CWE_TO_OWASP[cwe_id]
        return cat, OWASP_NAMES[cat], "exact"
    return "A02:2025", "Security Misconfiguration", "fallback"


def tags_to_owasp(tags: list[str]) -> tuple[str, str, str] | None:
    """Derive OWASP category from nuclei info.tags. Returns None if no tag matches."""
    tag_set = {t.lower() for t in tags}
    for match_tags, cat in TAG_TO_OWASP:
        if tag_set & match_tags:
            return cat, OWASP_NAMES[cat], "tag"
    return None

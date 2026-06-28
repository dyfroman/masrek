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

# OWASP Top 10 category numbers changed between editions.
# semgrep rules often carry 2021 tags — translate to 2025 taxonomy.
_OWASP_2021_TO_2025: dict[int, int] = {
    1: 1,    # Broken Access Control → Broken Access Control
    2: 4,    # Cryptographic Failures → Cryptographic Failures
    3: 5,    # Injection → Injection
    4: 6,    # Insecure Design → Insecure Design
    5: 2,    # Security Misconfiguration → Security Misconfiguration
    6: 3,    # Vulnerable & Outdated Components → Software Supply Chain Failures
    7: 7,    # Auth Failures → Authentication Failures
    8: 8,    # Software & Data Integrity → Software & Data Integrity
    9: 9,    # Logging Failures → Logging Failures
    10: 5,   # SSRF → Injection (SSRF is server-side request injection)
}
# 2017 edition also appears in some rules
_OWASP_2017_TO_2025: dict[int, int] = {
    1: 5,    # Injection → Injection
    2: 7,    # Broken Auth → Authentication Failures
    3: 4,    # Sensitive Data Exposure → Cryptographic Failures (2021 renamed this to A02 "Crypto Failures")
    4: 5,    # XXE → Injection
    5: 1,    # Broken Access Control → Broken Access Control
    6: 2,    # Security Misconfiguration → Security Misconfiguration
    7: 5,    # XSS → Injection
    8: 8,    # Insecure Deserialization → Software & Data Integrity
    9: 3,    # Using Components with Known Vulns → Supply Chain
    10: 9,   # Insufficient Logging → Logging Failures
}


def _map_severity(semgrep_sev: str) -> str:
    return _SEVERITY_MAP.get(semgrep_sev.upper(), "medium")


def _redact_secrets(text: str) -> str:
    return _SECRET_VALUE_RE.sub(r'\1=***REDACTED***', text)


def _translate_owasp_tag(num: int, tag_text: str) -> int:
    """Translate an OWASP tag number to the 2025 taxonomy."""
    tag_lower = tag_text.lower()
    if "2017" in tag_lower:
        return _OWASP_2017_TO_2025.get(num, num)
    if "2021" in tag_lower:
        return _OWASP_2021_TO_2025.get(num, num)
    if "2025" in tag_lower:
        return num
    # No edition specified — assume 2021 (most semgrep rules use 2021)
    return _OWASP_2021_TO_2025.get(num, num)


def _extract_owasp_from_metadata(metadata: dict) -> str | None:
    """Try to extract OWASP category from semgrep rule metadata.

    Translates 2017/2021 OWASP tag numbers to the 2025 taxonomy so
    that e.g. 2021-A03 (Injection) correctly maps to A05:2025.
    """
    owasp = metadata.get("owasp") or []
    if isinstance(owasp, str):
        owasp = [owasp]
    for entry in owasp:
        entry_str = str(entry)
        m = _SEMGREP_OWASP_RE.search(entry_str)
        if m:
            raw_num = int(m.group(1))
            if 1 <= raw_num <= 10:
                translated = _translate_owasp_tag(raw_num, entry_str)
                cat = f"A{translated:02d}:2025"
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

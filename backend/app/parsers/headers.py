"""Parser for passive/summary.json — missing security headers -> A02."""

from __future__ import annotations

from pathlib import Path

from ..models import ParsedFinding, redact_secret
from .base import safe_load_json

# Header -> (severity if missing, fix advice)
_HEADER_CHECKS: dict[str, tuple[str, str]] = {
    "content-security-policy": (
        "medium",
        "Add a Content-Security-Policy header. Start with: default-src 'self'; "
        "script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;",
    ),
    "strict-transport-security": (
        "medium",
        "Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
    ),
    "x-frame-options": (
        "low",
        "Add X-Frame-Options: DENY (or SAMEORIGIN if framing is needed).",
    ),
    "x-content-type-options": (
        "low",
        "Add X-Content-Type-Options: nosniff",
    ),
    "referrer-policy": (
        "low",
        "Add Referrer-Policy: strict-origin-when-cross-origin",
    ),
    "permissions-policy": (
        "info",
        "Add a Permissions-Policy header to restrict browser features.",
    ),
}


def parse(file_path: Path, run_id: str) -> list[ParsedFinding]:
    data = safe_load_json(file_path)
    if not data:
        return []

    findings: list[ParsedFinding] = []
    headers = data.get("security_headers", {})
    target = data.get("target", "")

    for header_name, (severity, fix) in _HEADER_CHECKS.items():
        info = headers.get(header_name, {})
        if not info.get("present", False):
            findings.append(ParsedFinding(
                severity=severity,
                title=f"Missing {header_name} header",
                category="A02:2025",
                category_name="Security Misconfiguration",
                location=target,
                evidence=f"Response does not include the {header_name} header",
                verified="yes",
                fix=fix,
                source_tool="passive-headers",
            ))

    # Server version disclosure
    server_info = data.get("server_info", {})
    server_val = server_info.get("server")
    powered_by = server_info.get("x-powered-by")
    if server_val:
        findings.append(ParsedFinding(
            severity="info",
            title="Server version disclosed",
            category="A02:2025",
            category_name="Security Misconfiguration",
            location=target,
            evidence=redact_secret(f"Server: {server_val}"),
            verified="yes",
            fix="Remove or genericize the Server header to avoid disclosing version info.",
            source_tool="passive-headers",
        ))
    if powered_by:
        findings.append(ParsedFinding(
            severity="low",
            title="X-Powered-By header discloses technology",
            category="A02:2025",
            category_name="Security Misconfiguration",
            location=target,
            evidence=redact_secret(f"X-Powered-By: {powered_by}"),
            verified="yes",
            fix="Remove the X-Powered-By header.",
            source_tool="passive-headers",
        ))

    return findings

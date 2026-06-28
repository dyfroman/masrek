"""Parser for gitleaks JSON output → OWASP A07/A02 findings with secret redaction.

CRITICAL: gitleaks returns FULL secret values in its output. This parser MUST
redact all secret values at parse time — before they ever reach the DB or API.
We store only: secret TYPE (rule ID), file:line, and a masked preview.
The raw gitleaks JSON in results/ is sensitive and stays local (gitignored).
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ..models import ParsedFinding
from .base import OWASP_NAMES, safe_load_json

logger = logging.getLogger("masrek.parsers.gitleaks")

_CREDENTIAL_RULES = {
    "generic-api-key", "private-key", "aws-access-key-id",
    "aws-secret-access-key", "github-pat", "github-oauth",
    "gitlab-pat", "slack-token", "stripe-api-key",
    "google-api-key", "heroku-api-key", "jwt",
    "hardcoded-password", "password-in-url",
}


_TYPE_PREFIXES = (
    "sk-proj-", "sk-live-", "sk-test-",
    "ghp_", "gho_", "ghs_", "ghu_", "github_pat_",
    "glpat-", "glsa-",
    "xoxb-", "xoxp-", "xoxo-", "xapp-",
    "sk_live_", "sk_test_", "rk_live_", "rk_test_",
    "AKIA", "ASIA",
    "eyJ",
)


def _mask_secret(value: str) -> str:
    """Mask a secret value, never exposing the entropy body or suffix.

    If the value starts with a known type prefix, show that prefix + "****".
    Otherwise fully mask as "********".
    """
    if not value:
        return "********"
    for prefix in _TYPE_PREFIXES:
        if value.startswith(prefix):
            return prefix + "****"
    return "********"


def _map_category(rule_id: str) -> tuple[str, str]:
    """Map gitleaks rule to OWASP category.

    Credential/auth secrets → A07. Config/misconfig secrets → A02.
    """
    rule_lower = rule_id.lower().replace("-", "").replace("_", "")

    if any(kw in rule_lower for kw in (
        "password", "credential", "token", "apikey", "secret",
        "pat", "oauth", "jwt", "privatekey", "accesskey",
    )):
        return "A07:2025", OWASP_NAMES["A07:2025"]

    return "A02:2025", OWASP_NAMES["A02:2025"]


_REDACT_RE = re.compile(
    r'(password|secret|token|key|credential|api.?key|passwd)\s*[:=]\s*\S+',
    re.IGNORECASE,
)


def _redact_text(text: str, secret_value: str) -> str:
    """Remove the raw secret value from any text, then apply general redaction."""
    if secret_value and secret_value in text:
        text = text.replace(secret_value, "****")
    return _REDACT_RE.sub(r'\1=***REDACTED***', text)


def _parse_finding(item: dict) -> ParsedFinding:
    rule_id = item.get("RuleID", item.get("ruleID", "unknown"))
    description = item.get("Description", item.get("description", rule_id))
    file_loc = item.get("File", item.get("file", "unknown"))
    line = item.get("StartLine", item.get("startLine", 0))
    secret = item.get("Secret", item.get("secret", ""))
    raw_match = item.get("Match", item.get("match", ""))

    category, category_name = _map_category(rule_id)
    masked = _mask_secret(secret)

    evidence_parts = [
        f"Secret type: {description}",
        f"Rule: {rule_id}",
        f"Masked value: {masked}",
    ]

    for field in ("entropy", "Entropy"):
        if field in item:
            evidence_parts.append(f"Entropy: {item[field]:.2f}")
            break

    evidence = "\n".join(evidence_parts)
    evidence = _redact_text(evidence, secret)

    title = f"{rule_id}: {description}"
    if len(title) > 200:
        title = title[:197] + "..."
    title = _redact_text(title, secret)

    fix = (
        f"Rotate the exposed {description} immediately. "
        f"Remove from source and use environment variables or a secrets manager."
    )

    return ParsedFinding(
        severity="high",
        title=title,
        category=category,
        category_name=category_name,
        location=f"{file_loc}:{line}",
        evidence=evidence,
        verified="yes",
        fix=fix,
        source_tool="gitleaks",
        mapping="exact",
    )


def parse(file_path: Path, run_id: str) -> list[ParsedFinding]:
    """Parse gitleaks JSON output into ParsedFinding objects.

    Every secret value is redacted before the finding is returned.
    """
    data = safe_load_json(file_path)
    if data is None:
        return []

    if not isinstance(data, list):
        return []

    findings: list[ParsedFinding] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        findings.append(_parse_finding(item))

    logger.info("gitleaks parser: %d findings from %s", len(findings), file_path)
    return findings

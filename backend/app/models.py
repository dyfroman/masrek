"""Pydantic models, finding-dedup logic, and secret redaction."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from enum import Enum
from typing import Optional
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

from pydantic import BaseModel, Field


# ── Enums ─────────────────────────────────────────────────────────────────────

class ScanMode(str, Enum):
    passive = "passive"
    active = "active"
    auto = "auto"


class RunStatus(str, Enum):
    queued = "queued"
    running = "running"
    done = "done"
    failed = "failed"
    timeout = "timeout"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


SEVERITY_ORDER = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}


class Verified(str, Enum):
    yes = "yes"
    no = "no"
    needs_manual = "needs-manual"


class OwaspCategory(str, Enum):
    A01 = "A01:2025"
    A02 = "A02:2025"
    A03 = "A03:2025"
    A04 = "A04:2025"
    A05 = "A05:2025"
    A06 = "A06:2025"
    A07 = "A07:2025"
    A08 = "A08:2025"
    A09 = "A09:2025"
    A10 = "A10:2025"


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


# ── Request / Response models ────────────────────────────────────────────────

class ScanType(str, Enum):
    baseline = "baseline"
    full = "full"


class TargetType(str, Enum):
    url = "url"
    source = "source"
    combined = "combined"


class ScanRequest(BaseModel):
    target_url: Optional[str] = None
    target_type: TargetType = TargetType.url
    source_path: Optional[str] = None
    mode: ScanMode = ScanMode.auto
    checks: Optional[list[str]] = None
    scan_type: ScanType = ScanType.baseline


class RunSummary(BaseModel):
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class RunResponse(BaseModel):
    run_id: str
    target_url: str
    target_host: str
    mode: str
    status: str
    created_at: str
    completed_at: Optional[str] = None
    summary: Optional[RunSummary] = None
    error_message: Optional[str] = None
    selected_checks: Optional[list[str]] = None
    scan_type: Optional[str] = None
    target_type: str = "url"
    source_path: Optional[str] = None


class FindingResponse(BaseModel):
    id: str
    severity: str
    title: str
    category: str
    category_name: str
    location: str
    evidence: Optional[str] = None
    verified: str
    fix: Optional[str] = None
    source_tool: str
    run_id: str
    mapping: str = "exact"


class RunDetailResponse(RunResponse):
    findings: list[FindingResponse] = Field(default_factory=list)


class ScopeResponse(BaseModel):
    allowlist: list[str]
    safety: dict


class ScopeCheckResponse(BaseModel):
    host: str
    in_scope: bool
    allowed_mode: str


# ── Parsed finding (internal, before DB insert) ──────────────────────────────

class ParsedFinding:
    """A finding produced by a parser, before dedup/merge/DB insertion."""
    __slots__ = (
        "severity", "title", "category", "category_name",
        "location", "evidence", "verified", "fix", "source_tool",
        "mapping",
    )

    def __init__(
        self, *, severity: str, title: str, category: str, category_name: str,
        location: str, evidence: str = "", verified: str = "no",
        fix: str = "", source_tool: str, mapping: str = "exact",
    ):
        self.severity = severity
        self.title = title
        self.category = category
        self.category_name = category_name
        self.location = location
        self.evidence = evidence
        self.verified = verified
        self.fix = fix
        self.source_tool = source_tool
        self.mapping = mapping


# ── Location normalization ───────────────────────────────────────────────────

_SOURCE_PREFIX_RE = re.compile(r"/app/source/")


def normalize_location(url: str, source_prefix: str | None = None) -> str:
    """Normalize a URL or file-path location for dedup.

    C2 decision: keep query parameter NAMES but zero their VALUES so that the
    same XSS on ?q=<payload-a> and ?q=<payload-b> dedupes to one finding.
    This ensures that scanner-generated payload variations don't create
    duplicate findings. The param name is kept because ?q= and ?search= may
    be genuinely different injection points.

    For SAST findings, strip the actual source_path prefix (e.g.
    /app/source/vulnerable-app/) so tools that use absolute vs relative paths
    (osv-scanner vs trivy) dedupe correctly regardless of mount depth.
    Falls back to stripping the generic /app/source/ prefix.
    """
    loc = url
    if source_prefix:
        sp = source_prefix.rstrip("/") + "/"
        loc = loc.replace(sp, "")
    loc = _SOURCE_PREFIX_RE.sub("", loc)
    parsed = urlparse(loc)
    if not parsed.query:
        return loc.lower().rstrip("/")
    params = parse_qs(parsed.query, keep_blank_values=True)
    zeroed = {k: ["0"] for k in sorted(params.keys())}
    new_query = urlencode(zeroed, doseq=True)
    normalized = urlunparse((
        parsed.scheme, parsed.netloc.lower(), parsed.path.rstrip("/"),
        parsed.params, new_query, "",
    ))
    return normalized


# ── Finding dedup ────────────────────────────────────────────────────────────

# Dedup fingerprint = SHA256(owasp_category + normalized_location + normalized_title)
# This collapses the same issue reported by different tools (e.g. ZAP + nuclei)
# into a single finding per run.

_NORMALIZE_RE = re.compile(r"[^a-z0-9/:.?=&]+")


def _normalize_text(s: str) -> str:
    return _NORMALIZE_RE.sub("", s.lower().strip())


def compute_dedupe_hash(
    owasp_category: str, location: str, title: str,
    source_prefix: str | None = None,
) -> str:
    norm_loc = normalize_location(location, source_prefix)
    key = f"{_normalize_text(owasp_category)}|{_normalize_text(norm_loc)}|{_normalize_text(title)}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


# ── Secret redaction ─────────────────────────────────────────────────────────

_SECRET_RE = re.compile(
    r"""(?x)
    (?:
        (?:api[_-]?key|password|secret|token|credential|auth)
        \s*[:=]\s*
    )
    ['"]?
    ([^\s'"]{8,})
    ['"]?
    |
    ['"]?
    ([A-Za-z0-9+/=_\-]{16,})
    ['"]?
    """
)


def redact_secret(raw_evidence: str) -> str:
    """Replace anything that looks like a secret value with a masked version.

    Used at parse time before the finding ever touches the database.
    Keeps the first 4 and last 2 characters, replaces the middle with ****.
    """
    def _mask(match: re.Match) -> str:
        token = match.group(1) or match.group(2)
        if len(token) <= 8:
            return "****"
        return token[:4] + "****" + token[-2:]

    return _SECRET_RE.sub(_mask, raw_evidence)


def redact_gitleaks_finding(evidence: str, file_path: str, line: int) -> str:
    """Build a redacted evidence string for a gitleaks-style secret finding."""
    return f"secret detected at {file_path}:{line} — {redact_secret(evidence)}"

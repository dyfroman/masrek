"""Canonical scope parser — single source of truth for authorization decisions.

Parses the SCOPE.md allowlist ONLY from between <!-- ALLOWLIST-START --> and
<!-- ALLOWLIST-END --> markers. A host mentioned anywhere else in the file
(e.g. the "forbidden" section) is NOT considered allowed.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

_START_MARKER = "<!-- ALLOWLIST-START -->"
_END_MARKER = "<!-- ALLOWLIST-END -->"
_SOURCE_START_MARKER = "<!-- SOURCE-ALLOWLIST-START -->"
_SOURCE_END_MARKER = "<!-- SOURCE-ALLOWLIST-END -->"

_SAFETY_PATTERN = re.compile(r"^(\w+):\s*(.+)$")


@dataclass(frozen=True)
class SafetyParams:
    rate_limit_rps: int = 10
    max_scan_minutes: int = 30
    destructive_tests: bool = False
    auth_brute_force: bool = False
    fail_gate_on: str = "high"


@dataclass(frozen=True)
class ScopeConfig:
    allowlist: tuple[str, ...] = field(default_factory=tuple)
    source_allowlist: tuple[str, ...] = field(default_factory=tuple)
    safety: SafetyParams = field(default_factory=SafetyParams)


def _default_scope_path() -> Path:
    env = os.environ.get("SCOPE_FILE")
    if env:
        return Path(env)
    return Path(__file__).resolve().parent.parent.parent / "SCOPE.md"


def parse_scope(scope_path: Path | None = None) -> ScopeConfig:
    """Parse SCOPE.md and return the allowlist + safety parameters."""
    path = scope_path or _default_scope_path()
    text = path.read_text(encoding="utf-8")

    # --- allowlist: ONLY between markers ---
    hosts: list[str] = []
    start = text.find(_START_MARKER)
    end = text.find(_END_MARKER)
    if start != -1 and end != -1:
        block = text[start + len(_START_MARKER):end]
        for line in block.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("<!--"):
                hosts.append(stripped)

    # --- source allowlist: paths authorized for SAST/SCA scanning ---
    source_paths: list[str] = []
    src_start = text.find(_SOURCE_START_MARKER)
    src_end = text.find(_SOURCE_END_MARKER)
    if src_start != -1 and src_end != -1:
        block = text[src_start + len(_SOURCE_START_MARKER):src_end]
        for line in block.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("<!--"):
                source_paths.append(stripped)

    # --- safety params: from the yaml block ---
    safety_kw: dict[str, int | bool | str] = {}
    in_yaml = False
    for line in text.splitlines():
        if line.strip() == "```yaml":
            in_yaml = True
            continue
        if in_yaml and line.strip() == "```":
            break
        if in_yaml:
            m = _SAFETY_PATTERN.match(line.strip())
            if m:
                key, raw = m.group(1), m.group(2).strip()
                if raw.isdigit():
                    safety_kw[key] = int(raw)
                elif raw.lower() in ("true", "false"):
                    safety_kw[key] = raw.lower() == "true"
                else:
                    safety_kw[key] = raw

    return ScopeConfig(
        allowlist=tuple(hosts),
        source_allowlist=tuple(source_paths),
        safety=SafetyParams(**{
            k: v for k, v in safety_kw.items()
            if k in SafetyParams.__dataclass_fields__
        }),
    )


def _host_port_from_url(url: str) -> str:
    """Extract host:port (or host if no explicit port) from a URL."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    port = parsed.port
    if port:
        return f"{host}:{port}"
    return host


def is_in_scope(target_url: str, scope: ScopeConfig | None = None) -> bool:
    """Check whether *target_url*'s host:port is in the SCOPE.md allowlist."""
    if scope is None:
        scope = parse_scope()
    target_hp = _host_port_from_url(target_url)
    if not target_hp:
        return False
    for allowed_url in scope.allowlist:
        if _host_port_from_url(allowed_url) == target_hp:
            return True
    return False


class SourcePathError(Exception):
    """Raised when a source path fails validation."""


def validate_source_path(
    source_path: str, scope: ScopeConfig | None = None,
) -> Path:
    """Validate and resolve a source path for SAST/SCA scanning.

    Resolves symlinks via realpath and confirms the result stays inside
    one of the SOURCE-ALLOWLIST entries (same principle as the DAST SSRF guard).
    Returns the resolved absolute path.
    """
    if scope is None:
        scope = parse_scope()

    if not source_path or not source_path.strip():
        raise SourcePathError("source_path is required for source scans.")

    if not scope.source_allowlist:
        raise SourcePathError(
            "No source paths authorized in SCOPE.md. "
            "Add paths between <!-- SOURCE-ALLOWLIST-START --> and "
            "<!-- SOURCE-ALLOWLIST-END --> markers."
        )

    candidate = Path(source_path)
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, ValueError) as exc:
        raise SourcePathError(f"Source path does not exist or is unresolvable: {exc}")

    if not resolved.is_dir():
        raise SourcePathError(f"Source path is not a directory: {resolved}")

    for allowed in scope.source_allowlist:
        allowed_resolved = Path(allowed).resolve(strict=False)
        try:
            resolved.relative_to(allowed_resolved)
            return resolved
        except ValueError:
            continue

    raise SourcePathError(
        f"Source path '{resolved}' is outside the authorized source allowlist. "
        f"Allowed: {list(scope.source_allowlist)}"
    )

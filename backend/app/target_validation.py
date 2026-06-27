"""Target URL validation and SSRF guard.

Validates that a target URL has an acceptable scheme and host, and blocks
requests to internal/private/metadata IPs — UNLESS the exact host is
present in the SCOPE.md allowlist (so allowlisted localhost:3000 passes).

A1: Returns the pinned (validated) IP so callers can thread it through to
scanners, preventing DNS rebinding / TOCTOU attacks.
B2: Also blocks is_unspecified and handles IPv4-mapped IPv6 addresses.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

from .scope import ScopeConfig, is_in_scope, parse_scope

_ALLOWED_SCHEMES = {"http", "https"}


class TargetValidationError(Exception):
    pass


@dataclass(frozen=True)
class ValidationResult:
    url: str
    hostname: str
    port: int | None
    pinned_ip: str | None  # None only for allowlisted hosts where resolution is skipped


def _is_private_or_reserved(ip_str: str) -> bool:
    """Return True if the IP is loopback, private (RFC1918), link-local,
    unspecified, or the cloud metadata address."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if addr.is_loopback:
        return True
    if addr.is_private:
        return True
    if addr.is_link_local:
        return True
    # B2: block unspecified (0.0.0.0, ::)
    if addr.is_unspecified:
        return True
    # Cloud metadata endpoint
    if ip_str in ("169.254.169.254", "fd00:ec2::254"):
        return True
    # B2: IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1) — re-check the mapped IPv4
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return _is_private_or_reserved(str(addr.ipv4_mapped))
    return False


def validate_target(
    target_url: str, scope: ScopeConfig | None = None
) -> ValidationResult:
    """Validate *target_url* and return a ValidationResult with the pinned IP.

    Raises TargetValidationError if the URL is invalid, uses a disallowed
    scheme, or resolves to a private/metadata IP that isn't allowlisted.
    """
    if scope is None:
        scope = parse_scope()

    parsed = urlparse(target_url)

    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise TargetValidationError(
            f"Scheme '{parsed.scheme}' is not allowed. Only http and https are accepted."
        )

    hostname = parsed.hostname
    if not hostname:
        raise TargetValidationError("URL has no hostname.")

    if any(c in hostname for c in (" ", "\t", "\n", "\r", "\x00")):
        raise TargetValidationError("Hostname contains invalid characters.")

    allowlisted = is_in_scope(target_url, scope)

    # Resolve and vet the IP — even for allowlisted hosts we resolve so we
    # can pin the IP, but we only BLOCK private IPs for non-allowlisted hosts.
    pinned_ip: str | None = None
    try:
        resolved = socket.getaddrinfo(
            hostname, parsed.port or (443 if parsed.scheme == "https" else 80),
            socket.AF_UNSPEC, socket.SOCK_STREAM,
        )
    except socket.gaierror:
        if allowlisted:
            # Allowlisted host that doesn't resolve yet (e.g. container not up)
            return ValidationResult(
                url=target_url, hostname=hostname,
                port=parsed.port, pinned_ip=None,
            )
        raise TargetValidationError(f"Cannot resolve hostname '{hostname}'.")

    for _family, _, _, _, sockaddr in resolved:
        ip_str = sockaddr[0]
        if not allowlisted and _is_private_or_reserved(ip_str):
            raise TargetValidationError(
                f"Host '{hostname}' resolves to private/reserved IP {ip_str}. "
                "Scanning internal addresses is blocked unless the host is "
                "in the SCOPE.md allowlist."
            )
        if pinned_ip is None:
            pinned_ip = ip_str

    return ValidationResult(
        url=target_url, hostname=hostname,
        port=parsed.port, pinned_ip=pinned_ip,
    )

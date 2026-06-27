"""API-key authentication middleware.

B1: Auth is REQUIRED by default (fail-closed). Disable ONLY by setting
MASREK_AUTH_DISABLED=1 explicitly (for localhost-only dev).

Set MASREK_API_KEY to the desired key. If auth is enabled but no key is
configured, ALL requests to protected endpoints are rejected (fail-closed).
The key is checked via constant-time comparison.
"""

from __future__ import annotations

import hmac
import os

from fastapi import HTTPException, Request


def _auth_disabled() -> bool:
    return os.environ.get("MASREK_AUTH_DISABLED", "").strip() == "1"


def _get_configured_key() -> str | None:
    key = os.environ.get("MASREK_API_KEY", "").strip()
    return key if key else None


def require_auth(request: Request) -> None:
    """Dependency that enforces API-key auth on protected routes.

    Auth is disabled ONLY when MASREK_AUTH_DISABLED=1 is set explicitly.
    Otherwise, MASREK_API_KEY must be set and a valid Bearer token provided.
    If MASREK_API_KEY is unset while auth is enabled, all requests are rejected.
    """
    if _auth_disabled():
        return

    configured = _get_configured_key()
    if configured is None:
        raise HTTPException(
            status_code=503,
            detail="MASREK_API_KEY is not configured. Set it or set MASREK_AUTH_DISABLED=1 for dev.",
        )

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing or malformed Authorization header. Use: Bearer <api-key>",
        )

    provided = auth_header[7:]
    if not hmac.compare_digest(provided, configured):
        raise HTTPException(status_code=403, detail="Invalid API key.")

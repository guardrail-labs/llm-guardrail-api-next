from __future__ import annotations

import os

from fastapi import HTTPException, Request

WWW = {"WWW-Authenticate": 'Bearer realm="guardrail-admin"'}


def _is_auth_disabled() -> bool:
    """Return True when admin auth is bypassed via env toggle."""
    return os.getenv("GUARDRAIL_DISABLE_AUTH", "0") == "1"


def _is_admin_auth_enabled() -> bool:
    """Return True when admin auth is explicitly enabled."""
    return os.getenv("ADMIN_UI_AUTH", "0") == "1"


def _expected_token() -> str:
    return (os.getenv("ADMIN_UI_TOKEN") or "").strip()


def require_admin(request: Request) -> None:
    """Dependency to protect admin JSON endpoints.

    Behavior:
      - If GUARDRAIL_DISABLE_AUTH=1 -> allow
      - Else if ADMIN_UI_AUTH!=1 -> allow
      - Else require Authorization: Bearer <ADMIN_UI_TOKEN>
    """
    if _is_auth_disabled():
        return
    if not _is_admin_auth_enabled():
        return

    expected = _expected_token()
    if not expected:
        raise HTTPException(status_code=401, detail="Admin UI token not set.", headers=WWW)

    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token.", headers=WWW)

    token = auth.split(" ", 1)[1].strip()
    if token != expected:
        raise HTTPException(status_code=401, detail="Invalid token.", headers=WWW)

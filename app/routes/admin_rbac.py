from __future__ import annotations

from fastapi import HTTPException, Request

from app.services import config_store


def require_admin(request: Request) -> None:
    """Minimal scaffold: gate admin POST endpoints behind a shared key when enabled."""

    if not config_store.is_admin_rbac_enabled():
        return

    expect = config_store.get_admin_api_key().strip()
    if not expect:
        raise HTTPException(status_code=503, detail="Admin RBAC enabled but admin_api_key not set")

    header = (request.headers.get("X-Admin-Key") or "").strip()
    cookie = (request.cookies.get("admin_key") or "").strip()

    if header == expect or cookie == expect:
        return

    raise HTTPException(status_code=403, detail="admin key required")

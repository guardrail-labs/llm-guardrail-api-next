from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

from fastapi import HTTPException, Request
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

from app import config

_ROLE_ORDER = {"viewer": 0, "operator": 1, "admin": 2}


def _normalize_role(role: Optional[str]) -> str:
    value = (role or "").strip().lower()
    if value in _ROLE_ORDER:
        return value
    return config.ADMIN_RBAC_DEFAULT_ROLE


def get_current_user(request: Request) -> Dict[str, Any] | None:
    try:
        session_obj = getattr(request, "session", None)
    except AssertionError:
        session_obj = None
    session: Mapping[str, Any] | None
    if isinstance(session_obj, Mapping):
        session = session_obj
    elif isinstance(session_obj, dict):  # pragma: no cover - defensive
        session = session_obj
    else:
        session = None
    user = session.get("user") if session is not None else None
    return user if isinstance(user, dict) else None


def _effective_role(user: Dict[str, Any] | None) -> str:
    if not user:
        return "anonymous"
    email = str(user.get("email") or "").strip().lower()
    if email and email in config.ADMIN_RBAC_OVERRIDES:
        return _normalize_role(config.ADMIN_RBAC_OVERRIDES[email])
    explicit = user.get("role")
    if explicit:
        return _normalize_role(str(explicit))
    roles = user.get("roles")
    if isinstance(roles, list) and roles:
        return _normalize_role(str(roles[0]))
    return _normalize_role(config.ADMIN_RBAC_DEFAULT_ROLE)


def effective_role(user: Dict[str, Any] | None) -> str:
    """Public helper for computing the effective role for a user payload."""

    return _effective_role(user)


def _ensure_authn(request: Request) -> Dict[str, Any]:
    if config.ADMIN_AUTH_MODE == "disabled":
        return {"email": "dev@local", "name": "Dev", "role": "admin"}
    user = get_current_user(request)
    if not user:
        raise HTTPException(HTTP_401_UNAUTHORIZED, "Authentication required")
    return user


def _require_min_role(request: Request, need: str) -> Dict[str, Any]:
    user = _ensure_authn(request)
    have = _effective_role(user)
    if have == "anonymous":
        raise HTTPException(HTTP_401_UNAUTHORIZED, "Authentication required")
    if _ROLE_ORDER.get(have, -1) < _ROLE_ORDER.get(need, 99):
        raise HTTPException(HTTP_403_FORBIDDEN, f"Requires {need} role")
    return user


def require_viewer(request: Request) -> Dict[str, Any]:
    return _require_min_role(request, "viewer")


def require_operator(request: Request) -> Dict[str, Any]:
    return _require_min_role(request, "operator")


def require_admin(request: Request) -> Dict[str, Any]:
    return _require_min_role(request, "admin")

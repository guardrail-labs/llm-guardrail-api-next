from __future__ import annotations

import asyncio
import importlib
import inspect
from typing import Any, Callable, Dict, Mapping, Optional, cast

from fastapi import HTTPException, Request
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

from app import config
from app.security import service_tokens as ST

_ROLE_ORDER = {"viewer": 0, "operator": 1, "admin": 2}


def _normalize_role(role: Optional[str]) -> str:
    value = (role or "").strip().lower()
    if value in _ROLE_ORDER:
        return value
    return config.ADMIN_RBAC_DEFAULT_ROLE


def get_current_user(request: Request) -> Dict[str, Any] | None:
    """Return the current admin session payload if present.

    When OIDC is enabled, the login flow populates this cookie-backed session.
    """

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


def _try_service_token(request: Request) -> Dict[str, Any] | None:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    token = auth.split(" ", 1)[1].strip()
    if not token:
        return None
    try:
        claims = ST.verify(token)
    except Exception:
        return None
    tenants = claims.get("tenants", "*")
    bots = claims.get("bots", "*")
    role_claim = str(claims.get("role") or "viewer")
    return {
        "email": f"{claims.get('sub', 'svc')}@tokens",
        "name": "Service Token",
        "role": _normalize_role(role_claim),
        "scope": {"tenants": tenants, "bots": bots},
        "svc": True,
        "jti": claims.get("jti"),
        "claims": claims,
    }


def _try_legacy_admin_token(request: Request) -> Dict[str, Any] | None:
    """Attempt to authenticate using legacy token-based admin auth."""

    authz = request.headers.get("authorization") or request.headers.get("Authorization")
    if not authz:
        return None
    try:
        legacy = importlib.import_module("app.security.admin_auth")
    except Exception:  # pragma: no cover - legacy module missing
        return None

    candidates = [
        "verify_request",
        "authenticate_request",
        "validate",
        "verify",
        "check",
        "require_auth",
    ]
    for name in candidates:
        fn = getattr(legacy, name, None)
        if not callable(fn):
            continue
        try:
            legacy_fn = cast(Callable[[Request], Any], fn)
            res = legacy_fn(request)
            if inspect.isawaitable(res):
                try:
                    import anyio

                    async def _await_it(coro: Any) -> Any:
                        return await coro

                    res = anyio.from_thread.run(_await_it, res)
                except Exception:
                    try:
                        asyncio.get_running_loop()
                    except RuntimeError:
                        res = asyncio.run(res)
                    else:
                        raise RuntimeError("running loop; cannot await legacy auth here")
        except Exception:  # pragma: no cover - try the next strategy
            continue
        identity = res if isinstance(res, dict) else {}
        email = identity.get("email") if isinstance(identity, dict) else None
        role = identity.get("role") if isinstance(identity, dict) else None
        name_ = identity.get("name") if isinstance(identity, dict) else None
        return {
            "email": email or "token@legacy",
            "name": name_ or "Token",
            "role": role or "operator",
        }
    return None


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
    svc_user = _try_service_token(request)
    if svc_user:
        setattr(request.state, "admin_user", svc_user)
        return svc_user
    state_user = getattr(request.state, "admin_user", None)
    if isinstance(state_user, dict) and state_user:
        return state_user
    if config.ADMIN_AUTH_MODE == "disabled":
        dev_user = {"email": "dev@local", "name": "Dev", "role": "admin"}
        setattr(request.state, "admin_user", dev_user)
        return dev_user
    user = get_current_user(request)
    if not user:
        legacy_user = _try_legacy_admin_token(request)
        if legacy_user:
            setattr(request.state, "admin_user", legacy_user)
            return legacy_user
        raise HTTPException(HTTP_401_UNAUTHORIZED, "Authentication required")
    setattr(request.state, "admin_user", user)
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


def _value_in_scope(scope_value: Any, candidate: Optional[str]) -> bool:
    if scope_value == "*":
        return True
    if candidate is None:
        return True
    if isinstance(scope_value, str):
        return scope_value == candidate
    try:
        return candidate in scope_value
    except Exception:
        return False


def _within_scope(user: dict[str, Any], tenant: Optional[str], bot: Optional[str]) -> bool:
    scope = user.get("scope") if isinstance(user, dict) else None
    if not scope:
        return True
    tenants = scope.get("tenants", "*") if isinstance(scope, dict) else "*"
    bots = scope.get("bots", "*") if isinstance(scope, dict) else "*"
    return _value_in_scope(tenants, tenant) and _value_in_scope(bots, bot)


def ensure_scope(
    user: dict[str, Any], *, tenant: Optional[str], bot: Optional[str]
) -> None:
    if not _within_scope(user, tenant, bot):
        raise HTTPException(HTTP_403_FORBIDDEN, "Out of scope")

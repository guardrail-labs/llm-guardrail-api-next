from __future__ import annotations

import asyncio
import importlib
import inspect
import os
from typing import Awaitable, Callable, Optional, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import PlainTextResponse

router = APIRouter()


def _truthy(val: object) -> bool:
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


def _settings_admin_key(request: Request) -> Optional[str]:
    """Best-effort read of settings.admin.key like other admin routes."""

    try:
        settings = getattr(request.app.state, "settings", None)
        admin = getattr(settings, "admin", None)
        key = getattr(admin, "key", None)
        if key:
            return str(key)
    except Exception:
        pass
    return None


def _rbac_enabled(request: Request) -> bool:
    """
    Determine if RBAC is enabled using (in order):
    - settings.admin.rbac_enabled (bool) if present
    - persisted config store: {"admin_rbac_enabled": bool}
    - env flags: ADMIN_RBAC_ENABLED / RBAC_ENABLED
    """

    # settings
    try:
        settings = getattr(request.app.state, "settings", None)
        admin = getattr(settings, "admin", None)
        val = getattr(admin, "rbac_enabled", None)
        if isinstance(val, bool):
            return val
    except Exception:
        pass

    # persisted config (config_store)
    try:
        from app.services import config_store as _cfg

        cfg_obj = None
        for attr in ("get_config", "current", "current_config", "read", "get"):
            try:
                fn = getattr(_cfg, attr, None)
                if callable(fn):
                    cfg_obj = fn()
                    break
                obj = getattr(_cfg, attr, None)
                if isinstance(obj, dict):
                    cfg_obj = obj
                    break
            except Exception:
                continue
        if isinstance(cfg_obj, dict):
            v = cfg_obj.get("admin_rbac_enabled")
            if isinstance(v, bool):
                return v
    except Exception:
        pass

    # env fallbacks
    for name in ("ADMIN_RBAC_ENABLED", "RBAC_ENABLED"):
        if _truthy(os.getenv(name, "false")):
            return True

    return False


GuardCallable = Callable[[Request], Awaitable[object] | object]


def _load_require_admin(request: Request) -> Optional[GuardCallable]:
    """
    Load a project-level admin guard with sensible precedence:
    - If RBAC is enabled: prefer admin_rbac, then admin_auth, then admin_common.
    - If RBAC is disabled: prefer admin_auth, then admin_rbac, then admin_common.
    """

    rbac_on = _rbac_enabled(request)
    if rbac_on:
        candidates = (
            ("app.routes.admin_rbac", "require_admin"),
            ("app.security.admin_auth", "require_admin"),
            ("app.routes.admin_common", "require_admin"),
        )
    else:
        candidates = (
            ("app.security.admin_auth", "require_admin"),
            ("app.routes.admin_rbac", "require_admin"),
            ("app.routes.admin_common", "require_admin"),
        )
    for mod_name, fn_name in candidates:
        try:
            mod = importlib.import_module(mod_name)
            fn = getattr(mod, fn_name, None)
            if callable(fn):
                return cast(GuardCallable, fn)
        except Exception:
            continue
    return None


async def _maybe_call_guard(guard: GuardCallable, request: Request) -> None:
    """
    Call the guard exactly once; if the return value is awaitable, await it.
    This supports plain async defs, decorated/partial callables, and objects with async __call__.
    """

    result = guard(request)
    if inspect.isawaitable(result):
        await cast(Awaitable[object], result)
    # If not awaitable, the guard has already run synchronously.


def _require_admin_dep(request: Request) -> None:
    """
    Require admin auth for this route:
    - Prefer project-wide guard (RBAC-aware precedence).
    - Else require X-Admin-Key matching env or settings.
    """

    guard = _load_require_admin(request)
    if callable(guard):
        # This dependency runs in FastAPI's threadpool (no event loop),
        # so we can safely drive async guards with asyncio.run.
        asyncio.run(_maybe_call_guard(guard, request))
        return

    # Fallback: header key from ENV first, then settings (align with other admin routes)
    env_key = os.getenv("ADMIN_API_KEY") or os.getenv("GUARDRAIL_ADMIN_KEY")
    cfg_key = _settings_admin_key(request)
    required = env_key or cfg_key
    if required:
        supplied = request.headers.get("X-Admin-Key")
        if str(supplied) != str(required):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")


@router.get("/admin/echo", dependencies=[Depends(_require_admin_dep)])
async def admin_echo(text: str = Query(..., description="Text to echo back")) -> PlainTextResponse:
    """
    Admin-only echo endpoint used for smoke and demos.

    This response passes through the egress redaction middleware, so any configured
    policy packs (e.g., PII/Secrets) will redact content in the echoed text.
    """

    return PlainTextResponse(text, media_type="text/plain; charset=utf-8")

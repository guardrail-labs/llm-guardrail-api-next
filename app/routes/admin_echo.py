from __future__ import annotations

import importlib
import os
from typing import Callable, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import PlainTextResponse

router = APIRouter()


def _load_require_admin() -> Callable[[Request], None] | None:
    for mod_name, fn_name in (
        ("app.routes.admin_rbac", "require_admin"),
        ("app.security.admin_auth", "require_admin"),
        ("app.routes.admin_common", "require_admin"),
    ):
        try:
            mod = importlib.import_module(mod_name)
            fn = getattr(mod, fn_name, None)
            if callable(fn):
                return cast(Callable[[Request], None], fn)
        except Exception:
            continue
    return None


def _require_admin_dep(request: Request) -> None:
    guard = _load_require_admin()
    if callable(guard):
        guard(request)
        return

    key = os.getenv("ADMIN_API_KEY") or os.getenv("GUARDRAIL_ADMIN_KEY")
    if key and request.headers.get("X-Admin-Key") != key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="admin key required",
        )


@router.get("/admin/echo", dependencies=[Depends(_require_admin_dep)])
async def admin_echo(text: str = Query(..., description="Text to echo back")) -> PlainTextResponse:
    """Echo back text to exercise redaction middleware."""

    return PlainTextResponse(text, media_type="text/plain; charset=utf-8")

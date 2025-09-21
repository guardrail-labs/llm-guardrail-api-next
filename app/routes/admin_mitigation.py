from __future__ import annotations

import importlib
from typing import Literal, Optional, cast

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.services import mitigation_prefs as prefs

router = APIRouter(prefix="/admin/api/mitigation", tags=["admin-mitigation"])


def _load_callable(path: str):
    module_name, _, attr = path.partition(":")
    if not module_name or not attr:
        return None
    try:
        mod = importlib.import_module(module_name)
    except Exception:
        return None
    fn = getattr(mod, attr, None)
    return fn if callable(fn) else None


def require_admin_session(request: Request) -> None:
    """Reuse existing admin auth/session guards when available."""

    last_error: HTTPException | None = None
    attempted = False
    for path in (
        "app.security.admin_auth:require_admin",
        "app.security.rbac:require_admin",
        "app.routes.admin_ui:require_auth",
    ):
        guard = _load_callable(path)
        if guard is None:
            continue
        attempted = True
        try:
            guard(request)
            return
        except HTTPException as exc:
            last_error = exc
            continue
        except Exception:
            continue

    if last_error is not None and attempted:
        raise last_error


def require_csrf(request: Request) -> None:
    """Best-effort CSRF validation using existing helpers when present."""

    checker = _load_callable("app.routes.admin_ui:_require_ui_csrf")
    token = request.headers.get("X-CSRF-Token") or ""

    # Skip when no checker or when the UI cookie isn't issued yet (e.g. direct API use).
    if checker is None:
        return
    if not request.cookies.get("ui_csrf") and not token:
        return
    checker(request, token)


class ModeResp(BaseModel):
    mode: Literal["block", "clarify", "redact"]
    source: Literal["explicit", "default"]


class ModeReq(BaseModel):
    tenant: str = Field(min_length=1)
    bot: str = Field(min_length=1)
    mode: str


def _policy_default() -> prefs.Mode:
    raw = "clarify"
    try:
        return prefs.validate_mode(raw)
    except ValueError:  # pragma: no cover - defensive fallback
        return "clarify"


@router.get("/modes", response_model=ModeResp)
def get_modes(
    tenant: str,
    bot: str,
    _: Optional[None] = Depends(require_admin_session),
) -> ModeResp:
    mode, source = prefs.resolve_mode(
        tenant=tenant,
        bot=bot,
        policy_default=_policy_default(),
    )
    return ModeResp(mode=mode, source=cast(Literal["explicit", "default"], source))


@router.put("/modes", response_model=ModeResp)
def put_modes(
    payload: ModeReq,
    _session: Optional[None] = Depends(require_admin_session),
    _csrf: Optional[None] = Depends(require_csrf),
) -> ModeResp:
    try:
        prefs.set_mode(payload.tenant, payload.bot, prefs.validate_mode(payload.mode))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    mode, source = prefs.resolve_mode(
        tenant=payload.tenant,
        bot=payload.bot,
        policy_default=_policy_default(),
    )
    return ModeResp(mode=mode, source=cast(Literal["explicit", "default"], source))

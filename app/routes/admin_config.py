from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import JSONResponse

from app.routes.admin_ui import _csrf_ok, require_auth
from app.services.config_store import get_config, set_config

router = APIRouter(prefix="/admin", tags=["admin-config"])


@router.get("/config")
def get_cfg(_: None = Depends(require_auth)) -> JSONResponse:
    return JSONResponse(get_config())


def _parse_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    if s in {"", "0", "false", "no", "off"}:
        return False
    if s in {"1", "true", "yes", "on"}:
        return True
    if s in {"none", "null"}:
        return None
    return True


def _parse_int(value: Any, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    s = str(value).strip()
    if s == "":
        return None
    try:
        return int(s)
    except ValueError as exc:  # pragma: no cover - defensive
        raise HTTPException(status_code=400, detail=f"Invalid integer for {field}") from exc


@router.post("/config")
async def post_cfg(
    request: Request,
    csrf_token: str = Form(...),
    lock_enable: Any = Form(None),
    lock_deny_as_execute: Any = Form(None),
    escalation_enabled: Any = Form(None),
    escalation_deny_threshold: Any = Form(None),
    escalation_window_secs: Any = Form(None),
    escalation_cooldown_secs: Any = Form(None),
    _: None = Depends(require_auth),
) -> JSONResponse:
    cookie = request.cookies.get("ui_csrf", "")
    if not (cookie and csrf_token and _csrf_ok(csrf_token) and _csrf_ok(cookie)):
        raise HTTPException(status_code=400, detail="CSRF failed")

    patch: Dict[str, Any] = {}

    bool_inputs = {
        "lock_enable": lock_enable,
        "lock_deny_as_execute": lock_deny_as_execute,
        "escalation_enabled": escalation_enabled,
    }
    for key, raw in bool_inputs.items():
        parsed = _parse_bool(raw)
        if parsed is not None:
            patch[key] = parsed

    int_inputs = {
        "escalation_deny_threshold": escalation_deny_threshold,
        "escalation_window_secs": escalation_window_secs,
        "escalation_cooldown_secs": escalation_cooldown_secs,
    }
    for key, raw in int_inputs.items():
        parsed = _parse_int(raw, key)
        if parsed is not None:
            patch[key] = parsed

    cfg = set_config(patch, actor="admin-ui")
    return JSONResponse(cfg, status_code=status.HTTP_200_OK)

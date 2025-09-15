# app/routes/admin_config.py
from __future__ import annotations
from typing import Any, Optional
from fastapi import APIRouter, Depends, Request, HTTPException, status, Form
from fastapi.responses import JSONResponse
from app.services.config_store import get_config, set_config
from app.routes.admin_ui import require_auth, _csrf_ok  # reuse auth + CSRF helpers

router = APIRouter(prefix="/admin", tags=["admin-config"])

def _parse_bool(val: Any) -> Optional[bool]:
    if val is None:
        return None
    s = str(val).strip().lower()
    if s in ("true", "1", "yes", "on"):
        return True
    if s in ("false", "0", "no", "off"):
        return False
    return None

def _parse_int(val: Any) -> Optional[int]:
    if val is None or val == "":
        return None
    try:
        return int(str(val).strip())
    except Exception:
        return None

@router.get("/config")
def get_cfg(_: None = Depends(require_auth)):
    return JSONResponse(get_config())

@router.post("/config")
async def post_cfg(
    request: Request,
    csrf_token: str = Form(...),
    lock_enable: str | None = Form(None),
    lock_deny_as_execute: str | None = Form(None),
    escalation_enabled: str | None = Form(None),
    escalation_deny_threshold: str | None = Form(None),
    escalation_window_secs: str | None = Form(None),
    escalation_cooldown_secs: str | None = Form(None),
    _: None = Depends(require_auth),
):
    cookie = request.cookies.get("ui_csrf", "")
    if not (cookie and csrf_token and _csrf_ok(csrf_token) and _csrf_ok(cookie)):
        raise HTTPException(status_code=400, detail="CSRF failed")

    patch: dict[str, Any] = {}

    b_lock = _parse_bool(lock_enable)
    if b_lock is not None:
        patch["lock_enable"] = b_lock

    b_lock_deny = _parse_bool(lock_deny_as_execute)
    if b_lock_deny is not None:
        patch["lock_deny_as_execute"] = b_lock_deny

    b_escal = _parse_bool(escalation_enabled)
    if b_escal is not None:
        patch["escalation_enabled"] = b_escal

    i_thr = _parse_int(escalation_deny_threshold)
    if i_thr is not None:
        patch["escalation_deny_threshold"] = i_thr

    i_win = _parse_int(escalation_window_secs)
    if i_win is not None:
        patch["escalation_window_secs"] = i_win

    i_cool = _parse_int(escalation_cooldown_secs)
    if i_cool is not None:
        patch["escalation_cooldown_secs"] = i_cool

    cfg = set_config(patch, actor="admin-ui")
    return JSONResponse(cfg, status_code=status.HTTP_200_OK)

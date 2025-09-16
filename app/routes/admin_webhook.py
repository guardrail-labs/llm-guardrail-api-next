from __future__ import annotations

import time
from hmac import compare_digest
from typing import Any, Dict, Mapping, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse

from app.routes.admin_ui import _csrf_ok, require_auth
from app.services import webhooks as wh
from app.services.config_store import get_config, set_config

router = APIRouter(prefix="/admin", tags=["admin-webhook"])


def _csrf_token(request: Request, payload: Optional[Mapping[str, Any]]) -> Optional[str]:
    header_token = request.headers.get("x-csrf-token")
    if header_token:
        return header_token
    if payload and isinstance(payload, Mapping):
        token = payload.get("csrf_token")
        if isinstance(token, str) and token:
            return token
    return None


def _csrf_check_or_400(request: Request, token: Optional[str]) -> None:
    cookie = request.cookies.get("ui_csrf", "")
    ok = bool(
        cookie
        and token
        and _csrf_ok(cookie)
        and _csrf_ok(token)
        and compare_digest(cookie, token)
    )
    if not ok:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="CSRF failed")


@router.get("/webhook/config")
def get_webhook_cfg(_: None = Depends(require_auth)) -> JSONResponse:
    cfg = get_config()
    keys = (
        "webhook_enable",
        "webhook_url",
        "webhook_timeout_ms",
        "webhook_max_retries",
        "webhook_backoff_ms",
        "webhook_allow_insecure_tls",
        "webhook_allowlist_host",
    )
    redacted = {k: cfg.get(k) for k in keys}
    redacted["webhook_secret_set"] = bool(cfg.get("webhook_secret"))
    return JSONResponse(redacted)


@router.post("/webhook/config")
async def set_webhook_cfg(request: Request, _: None = Depends(require_auth)) -> JSONResponse:
    content_type = (request.headers.get("content-type") or "").lower()
    if "application/json" in content_type:
        try:
            payload = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="invalid json")
        if not isinstance(payload, Mapping):
            raise HTTPException(status_code=400, detail="invalid payload")
        _csrf_check_or_400(request, _csrf_token(request, payload))
        set_config(dict(payload))
        return JSONResponse(get_config(), status_code=200)

    form = await request.form()
    token = str(form.get("csrf_token") or "")
    _csrf_check_or_400(request, token)
    form_payload: Dict[str, Any] = {k: v for k, v in form.items() if k != "csrf_token"}
    set_config(form_payload)
    return JSONResponse(get_config(), status_code=200)


@router.post("/webhook/test")
async def webhook_test(request: Request, _: None = Depends(require_auth)) -> JSONResponse:
    content_type = (request.headers.get("content-type") or "").lower()
    token: Optional[str] = None
    if "application/json" in content_type:
        try:
            payload = await request.json()
        except Exception:
            payload = {}
        token = _csrf_token(request, payload if isinstance(payload, Mapping) else None)
    else:
        try:
            form = await request.form()
            token = str(form.get("csrf_token") or "")
        except Exception:
            token = None
    _csrf_check_or_400(request, token)

    cfg = get_config()
    if not (cfg.get("webhook_enable") and cfg.get("webhook_url")):
        return JSONResponse({"ok": False, "reason": "webhook disabled"}, status_code=200)

    now = int(time.time())
    evt = {
        "ts": now,
        "incident_id": f"test-{now}",
        "request_id": f"test-{now}",
        "tenant": "demo",
        "bot": "demo",
        "family": "allow",
        "mode": "allow",
        "status": 200,
        "endpoint": "/guardrail/evaluate",
        "rule_ids": [],
        "policy_version": "test",
        "shadow_action": None,
        "shadow_rule_ids": [],
    }
    wh.enqueue(evt)
    return JSONResponse({"ok": True})

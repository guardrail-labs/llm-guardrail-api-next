from __future__ import annotations

import hashlib
import hmac
import io
import os
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

from app.services.config_store import get_config, get_policy_packs
from app.services.policy import current_rules_version, reload_rules

# Best-effort helpers that may not exist in all deployments
try:  # pragma: no cover - optional dependency
    from app.services.bindings import list_bindings
except Exception:  # pragma: no cover - import error fallback
    def list_bindings() -> List[Dict[str, Any]]:
        return []

try:  # pragma: no cover - optional dependency
    from app.services.audit_forwarder import fetch_recent_decisions  # type: ignore
except Exception:  # pragma: no cover - missing audit store
    def fetch_recent_decisions(n: int = 50) -> List[Dict[str, Any]]:
        return []


router = APIRouter(tags=["admin-ui"])
templates = Jinja2Templates(directory="app/ui/templates")


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def _csrf_secret() -> str:
    return (
        os.getenv("ADMIN_UI_SECRET")
        or os.getenv("APP_SECRET")
        or os.getenv("SECRET_KEY")
        or "changeme-admin-ui"
    )


def _bearer_ok(req: Request) -> bool:
    token = os.getenv("ADMIN_UI_TOKEN")
    if not token:
        return False
    auth = req.headers.get("Authorization", "")
    return auth.startswith("Bearer ") and auth[7:] == token


def _basic_ok(req: Request) -> bool:
    if os.getenv("ADMIN_UI_TOKEN"):
        return False  # prefer bearer when set
    user = os.getenv("ADMIN_UI_USER")
    password = os.getenv("ADMIN_UI_PASS")
    if not (user and password):
        return False
    import base64

    auth = req.headers.get("Authorization", "")
    if not auth.startswith("Basic "):
        return False
    try:
        user_pass = base64.b64decode(auth[6:]).decode("utf-8")
        u, p = user_pass.split(":", 1)
        return u == user and p == password
    except Exception:  # pragma: no cover - malformed header
        return False


def require_auth(req: Request) -> None:
    if _bearer_ok(req) or _basic_ok(req):
        return
    headers = {"WWW-Authenticate": "Bearer" if os.getenv("ADMIN_UI_TOKEN") else "Basic"}
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Auth required",
        headers=headers,
    )


# ---------------------------------------------------------------------------
# CSRF helpers (double submit cookie)
# ---------------------------------------------------------------------------
def _csrf_token(ts: Optional[int] = None) -> str:
    ts = ts or int(time.time())
    msg = f"csrf|{ts}".encode("utf-8")
    sig = hmac.new(_csrf_secret().encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return f"{ts}.{sig}"


def _csrf_ok(token: str) -> bool:
    try:
        ts_s, sig = token.split(".", 1)
        ts = int(ts_s)
        if abs(int(time.time()) - ts) > 3600:
            return False
        msg = f"csrf|{ts}".encode("utf-8")
        expect = hmac.new(_csrf_secret().encode("utf-8"), msg, hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expect)
    except Exception:  # pragma: no cover - parse errors
        return False


def _csrf_cookie_secure() -> bool:
    raw = (os.getenv("ADMIN_UI_COOKIE_SECURE") or "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def issue_csrf(resp: Response, token: Optional[str] = None) -> str:
    token = token or _csrf_token()
    resp.set_cookie(
        "ui_csrf",
        token,
        httponly=False,
        samesite="strict",
        secure=_csrf_cookie_secure(),
    )
    return token


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
@router.get("/admin/ui", response_class=HTMLResponse)
def ui_overview(req: Request, _: None = Depends(require_auth)) -> HTMLResponse:
    resp = templates.TemplateResponse(
        "overview.html",
        {
            "request": req,
            "policy_version": current_rules_version(),
            "grafana_url": os.getenv("GRAFANA_URL"),
        },
    )
    issue_csrf(resp)
    return resp


@router.get("/admin/ui/bindings", response_class=HTMLResponse)
def ui_bindings(req: Request, _: None = Depends(require_auth)) -> HTMLResponse:
    try:
        bindings = list_bindings()
    except Exception:  # pragma: no cover - underlying store failure
        bindings = []
    resp = templates.TemplateResponse(
        "bindings.html", {"request": req, "bindings": bindings}
    )
    issue_csrf(resp)
    return resp


@router.get("/admin/ui/decisions", response_class=HTMLResponse)
def ui_decisions(
    req: Request, n: int = 50, _: None = Depends(require_auth)
) -> HTMLResponse:
    decisions = fetch_recent_decisions(n)
    resp = templates.TemplateResponse(
        "decisions.html",
        {"request": req, "decisions": decisions, "n": n},
    )
    issue_csrf(resp)
    return resp


@router.get("/admin/ui/config", response_class=HTMLResponse)
def ui_config(req: Request, _: None = Depends(require_auth)) -> HTMLResponse:
    cfg = get_config()
    resp = templates.TemplateResponse(
        "config.html",
        {
            "request": req,
            "config": cfg,
        },
    )
    issue_csrf(resp)
    return resp


@router.get("/admin/ui/config/history", response_class=HTMLResponse)
def ui_config_history(
    req: Request, _: None = Depends(require_auth)
) -> HTMLResponse:
    resp = templates.TemplateResponse("config_history.html", {"request": req})
    issue_csrf(resp)
    return resp


@router.get("/admin/ui/webhooks", response_class=HTMLResponse)
def ui_webhooks(req: Request, _: None = Depends(require_auth)) -> HTMLResponse:
    raw_cfg: Dict[str, Any] = dict(get_config())

    def _int_val(key: str, default: int) -> int:
        value = raw_cfg.get(key)
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            try:
                return int(value)
            except ValueError:
                return default
        return default

    cfg = {
        "webhook_enable": bool(raw_cfg.get("webhook_enable", False)),
        "webhook_url": raw_cfg.get("webhook_url") or "",
        "webhook_secret": raw_cfg.get("webhook_secret") or "",
        "webhook_timeout_ms": _int_val("webhook_timeout_ms", 2000),
        "webhook_max_retries": _int_val("webhook_max_retries", 5),
        "webhook_backoff_ms": _int_val("webhook_backoff_ms", 500),
        "webhook_allow_insecure_tls": bool(
            raw_cfg.get("webhook_allow_insecure_tls", False)
        ),
        "webhook_allowlist_host": raw_cfg.get("webhook_allowlist_host") or "",
    }

    csrf_token = _csrf_token()
    resp = templates.TemplateResponse(
        "webhooks.html",
        {
            "request": req,
            "cfg": cfg,
            "csrf_token": csrf_token,
        },
    )
    issue_csrf(resp, csrf_token)
    return resp


@router.get("/admin/policy", response_class=HTMLResponse)
def policy_page(
    request: Request, _: None = Depends(require_auth)
) -> HTMLResponse:
    """Render Policy admin page with active version and configured packs."""

    csrf_token = _csrf_token()
    version = current_rules_version()
    packs = get_policy_packs()
    resp = templates.TemplateResponse(
        "policy.html",
        {
            "request": request,
            "csrf_token": csrf_token,
            "version": version,
            "packs": packs,
        },
    )
    issue_csrf(resp, csrf_token)
    return resp


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------
@router.post("/admin/ui/reload", response_class=PlainTextResponse)
def ui_reload(
    req: Request, csrf_token: str = Form(...), _: None = Depends(require_auth)
) -> PlainTextResponse:
    cookie = req.cookies.get("ui_csrf", "")
    if not (
        cookie
        and csrf_token
        and _csrf_ok(csrf_token)
        and _csrf_ok(cookie)
        and hmac.compare_digest(cookie, csrf_token)
    ):
        raise HTTPException(status_code=400, detail="CSRF failed")
    try:
        reload_rules()
        return PlainTextResponse("ok")
    except Exception as exc:  # pragma: no cover - reload failure
        raise HTTPException(status_code=500, detail=f"reload failed: {exc}")


@router.get("/admin/ui/export/decisions")
def export_decisions(
    n: int = 1000, _: None = Depends(require_auth)
) -> StreamingResponse:
    buf = io.StringIO()
    for item in fetch_recent_decisions(n):
        import json

        buf.write(json.dumps(item) + "\n")
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/x-ndjson",
        headers={"Content-Disposition": "attachment; filename=decisions.ndjson"},
    )


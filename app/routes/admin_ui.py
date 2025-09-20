from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

from app.routes.admin_apply_demo_defaults import apply_demo_defaults as apply_demo_action
from app.routes.admin_apply_golden import apply_golden_packs as apply_golden_action
from app.routes.admin_apply_strict_secrets import apply_strict_secrets as apply_strict_action
from app.services.config_store import get_config, get_policy_packs
from app.services.policy import current_rules_version, reload_rules

if TYPE_CHECKING:
    from app.routes import admin_decisions as _admin_decisions_mod  # noqa: F401

# Best-effort helpers that may not exist in all deployments
try:  # pragma: no cover - optional dependency
    from app.services.bindings import list_bindings
except Exception:  # pragma: no cover - import error fallback
    def list_bindings() -> List[Dict[str, Any]]:
        return []

try:  # pragma: no cover - optional dependency
    from app.services.mitigation_modes import get_modes as get_mitigation_modes
except Exception:  # pragma: no cover - mitigation store unavailable
    def get_mitigation_modes(tenant: str, bot: str) -> Dict[str, bool]:
        return {"block": False, "redact": False, "clarify_first": False}

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


def _decisions_mod():
    from app.routes import admin_decisions as _admin_decisions

    return _admin_decisions


def _adjudications_mod():
    from app.routes import admin_adjudications as _admin_adjudications

    return _admin_adjudications


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
    tenant = req.query_params.get("tenant", "")
    bot = req.query_params.get("bot", "")
    if tenant and bot:
        mitigation_modes = get_mitigation_modes(tenant, bot)
    else:
        mitigation_modes = {"block": False, "redact": False, "clarify_first": False}
    resp = templates.TemplateResponse(
        "bindings.html",
        {
            "request": req,
            "bindings": bindings,
            "tenant": tenant,
            "bot": bot,
            "mitigation_modes": mitigation_modes,
        },
    )
    issue_csrf(resp)
    return resp


@router.get("/admin/ui/bindings/data", response_class=JSONResponse)
def ui_bindings_data(_: None = Depends(require_auth)) -> JSONResponse:
    try:
        bindings = list_bindings()
    except Exception:  # pragma: no cover - underlying store failure
        bindings = []
    return JSONResponse({"bindings": bindings})


def _epoch_to_iso(raw: Optional[Union[str, int, float]]) -> str:
    if raw in (None, ""):
        return ""
    if isinstance(raw, (int, float)):
        try:
            dt = datetime.fromtimestamp(float(raw), tz=timezone.utc)
            return dt.isoformat().replace("+00:00", "Z")
        except Exception:
            return str(raw)
    text = str(raw).strip()
    if not text:
        return ""
    try:
        value = int(text)
    except ValueError:
        try:
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            dt = datetime.fromisoformat(text)
        except Exception:
            return str(raw)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    try:
        dt = datetime.fromtimestamp(value, tz=timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    except Exception:
        return str(raw)


def _coerce_epoch(raw: Optional[str]) -> Optional[int]:
    if raw is None:
        return None
    text = raw.strip()
    if not text:
        return None
    try:
        value = int(text)
    except Exception:
        return None
    return value


def _format_ts(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (int, float)):
        try:
            formatted = datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
            return formatted.replace("+00:00", "Z")
        except Exception:
            return str(value)
    text = str(value)
    if not text:
        return ""
    if text.isdigit():
        try:
            formatted = datetime.fromtimestamp(int(text), tz=timezone.utc).isoformat()
            return formatted.replace("+00:00", "Z")
        except Exception:
            return text
    try:
        clean = text.rstrip("Z") + ("+00:00" if text.endswith("Z") else "")
        dt = datetime.fromisoformat(clean)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        return text


def _first_non_empty(*values: Any) -> str:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def _datetime_to_epoch(dt: Optional[datetime]) -> Optional[int]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.astimezone(timezone.utc).timestamp())


def _render_decision_row(item: Dict[str, Any]) -> Dict[str, str]:
    raw_details = item.get("details")
    details: Dict[str, Any] = raw_details if isinstance(raw_details, dict) else {}
    snippet = _first_non_empty(
        item.get("summary"),
        item.get("message"),
        details.get("summary"),
        details.get("message"),
        details.get("prompt"),
        details.get("text"),
    )
    return {
        "ts": _format_ts(item.get("ts")),
        "tenant": str(item.get("tenant") or ""),
        "bot": str(item.get("bot") or ""),
        "decision": str(item.get("decision") or ""),
        "rule_id": str(item.get("rule_id") or ""),
        "mitigation_forced": str(item.get("mitigation_forced") or ""),
        "snippet": snippet,
    }


def _render_adjudication_row(item: Dict[str, Any]) -> Dict[str, str]:
    rule_hits = item.get("rule_hits")
    rule_id = ""
    if isinstance(rule_hits, list) and rule_hits:
        try:
            rule_id = str(rule_hits[0])
        except Exception:
            rule_id = ""
    rules_path = str(item.get("rules_path") or "")
    if rules_path and rule_id:
        rule_ref = f"{rules_path} / {rule_id}"
    else:
        rule_ref = rules_path or rule_id

    raw_details = item.get("details")
    details: Dict[str, Any] = raw_details if isinstance(raw_details, dict) else {}
    snippet = _first_non_empty(
        item.get("notes"),
        item.get("message"),
        item.get("summary"),
        details.get("notes"),
        details.get("message"),
        details.get("summary"),
        details.get("prompt"),
        details.get("text"),
    )

    return {
        "ts": _format_ts(item.get("ts")),
        "tenant": str(item.get("tenant") or ""),
        "bot": str(item.get("bot") or ""),
        "decision": str(item.get("decision") or ""),
        "mitigation_forced": str(item.get("mitigation_forced") or ""),
        "rule_ref": rule_ref,
        "snippet": snippet,
    }


@router.get("/admin/ui/decisions", response_class=HTMLResponse)
def ui_decisions(req: Request, _: None = Depends(require_auth)) -> HTMLResponse:
    query = req.query_params
    raw_filters: Dict[str, Optional[str]] = {
        "tenant": query.get("tenant", ""),
        "bot": query.get("bot", ""),
        "rule_id": query.get("rule_id", ""),
        "decision": query.get("decision", ""),
        "from_ts": query.get("from_ts", ""),
        "to_ts": query.get("to_ts", ""),
        "limit": query.get("limit", ""),
        "offset": query.get("offset", ""),
        "sort": query.get("sort", ""),
    }

    decisions_mod = _decisions_mod()

    filters, error = decisions_mod._parse_filters(
        tenant=raw_filters["tenant"],
        bot=raw_filters["bot"],
        rule_id=raw_filters["rule_id"],
        decision=raw_filters["decision"],
        from_ts=raw_filters["from_ts"],
        to_ts=raw_filters["to_ts"],
        limit=raw_filters["limit"],
        offset=raw_filters["offset"],
        sort=raw_filters["sort"],
    )

    error_message: Optional[str] = None
    if error is not None:
        try:
            body_bytes = bytes(error.body)
            payload = json.loads(body_bytes.decode("utf-8"))
            error_message = str(payload.get("error") or "Invalid filters")
        except Exception:
            error_message = "Invalid filters"

    filters_state: Dict[str, Any]
    items: List[Dict[str, Any]] = []
    total = 0
    if filters is not None:
        records = decisions_mod.list_decisions(
            tenant=filters["tenant"],
            bot=filters["bot"],
            rule_id=filters["rule_id"],
            decision=filters["decision"],
            from_ts=filters["from_ts"],
            to_ts=filters["to_ts"],
            sort=filters["sort"],
        )
        total = len(records)
        start = filters["offset"]
        end = start + filters["limit"]
        slice_items = records[start:end]
        items = decisions_mod._serialize_items(slice_items)
        filters_state = {
            "tenant": filters["tenant"] or "",
            "bot": filters["bot"] or "",
            "rule_id": filters["rule_id"] or "",
            "decision": filters["decision"] or "",
            "from_ts": filters["from_ts"],
            "to_ts": filters["to_ts"],
            "sort": filters["sort"],
            "limit": filters["limit"],
            "offset": filters["offset"],
        }
    else:
        filters_state = {
            "tenant": (raw_filters["tenant"] or "").strip(),
            "bot": (raw_filters["bot"] or "").strip(),
            "rule_id": (raw_filters["rule_id"] or "").strip(),
            "decision": (raw_filters["decision"] or "").strip(),
            "from_ts": _coerce_epoch(raw_filters["from_ts"]),
            "to_ts": _coerce_epoch(raw_filters["to_ts"]),
            "sort": "ts_desc",
            "limit": 50,
            "offset": 0,
        }

    rendered_items = [_render_decision_row(item) for item in items]

    current_limit = int(filters_state.get("limit", 50))
    current_offset = int(filters_state.get("offset", 0))
    current_sort = filters_state.get("sort", "ts_desc") or "ts_desc"

    visible_count = len(items)
    if total <= 0 and visible_count > 0:
        total = current_offset + visible_count
    range_start = 0 if total == 0 or visible_count == 0 else current_offset + 1
    if total == 0:
        range_end = current_offset + visible_count
    else:
        range_end = min(total, current_offset + visible_count)
    disable_next = total > 0 and current_offset + current_limit >= total

    filter_inputs = {
        "tenant": filters_state.get("tenant", ""),
        "bot": filters_state.get("bot", ""),
        "rule_id": filters_state.get("rule_id", ""),
        "decision": filters_state.get("decision", ""),
        "from_ts": _epoch_to_iso(filters_state.get("from_ts")),
        "to_ts": _epoch_to_iso(filters_state.get("to_ts")),
    }

    ndjson_params: Dict[str, str] = {}
    for key in ("tenant", "bot", "rule_id", "decision"):
        value = filters_state.get(key)
        if value:
            ndjson_params[key] = str(value)
    for key in ("from_ts", "to_ts"):
        value = filters_state.get(key)
        if value not in (None, ""):
            ndjson_params[key] = str(value)
    sort_val = filters_state.get("sort")
    if sort_val:
        ndjson_params["sort"] = str(sort_val)
    ndjson_query = urlencode(ndjson_params)
    ndjson_url = "/admin/decisions.ndjson" + (f"?{ndjson_query}" if ndjson_query else "")

    bootstrap_state = {
        "filters": filters_state,
        "items": items,
        "total": total,
        "error": error_message,
    }

    resp = templates.TemplateResponse(
        "decisions.html",
        {
            "request": req,
            "filter_inputs": filter_inputs,
            "rendered_items": rendered_items,
            "current_limit": current_limit,
            "current_offset": current_offset,
            "current_sort": current_sort,
            "display_range": {"start": range_start, "end": range_end},
            "total_count": total,
            "disable_next": disable_next,
            "error_message": error_message,
            "ndjson_url": ndjson_url,
            "bootstrap_state": bootstrap_state,
        },
    )
    issue_csrf(resp)
    return resp


@router.get("/admin/ui/adjudications", response_class=HTMLResponse)
def ui_adjudications(req: Request, _: None = Depends(require_auth)) -> HTMLResponse:
    query = req.query_params
    raw_filters: Dict[str, Optional[str]] = {
        "tenant": query.get("tenant", ""),
        "bot": query.get("bot", ""),
        "decision": query.get("decision", ""),
        "mitigation_forced": query.get("mitigation_forced", ""),
        "from_ts": query.get("from_ts", ""),
        "to_ts": query.get("to_ts", ""),
        "limit": query.get("limit", ""),
        "offset": query.get("offset", ""),
        "sort": query.get("sort", ""),
    }

    adjudications_mod = _adjudications_mod()

    filters, error = adjudications_mod._parse_filters(
        tenant=raw_filters["tenant"],
        bot=raw_filters["bot"],
        provider=None,
        request_id=None,
        decision=raw_filters["decision"],
        mitigation_forced=raw_filters["mitigation_forced"],
        start=None,
        end=None,
        from_ts=raw_filters["from_ts"],
        to_ts=raw_filters["to_ts"],
        limit=raw_filters["limit"],
        offset=raw_filters["offset"],
        sort=raw_filters["sort"],
    )

    error_message: Optional[str] = None
    if error is not None:
        try:
            body_bytes = bytes(error.body)
            payload = json.loads(body_bytes.decode("utf-8"))
            error_message = str(payload.get("error") or "Invalid filters")
        except Exception:
            error_message = "Invalid filters"

    filters_state: Dict[str, Any]
    items: List[Dict[str, Any]] = []
    total = 0
    if filters is not None:
        records, total = adjudications_mod.adjudication_log.paged_query(
            start=filters["from_dt"],
            end=filters["to_dt"],
            tenant=filters["tenant"],
            bot=filters["bot"],
            provider=filters["provider"],
            request_id=filters["request_id"],
            decision=filters["decision"],
            mitigation_forced=filters["mitigation_forced"],
            limit=filters["limit"],
            offset=filters["offset"],
            sort=filters["sort"],
        )
        items = [adjudications_mod._serialize_record(record) for record in records]
        filters_state = {
            "tenant": filters["tenant"] or "",
            "bot": filters["bot"] or "",
            "decision": filters["decision"] or "",
            "mitigation_forced": filters["mitigation_forced"]
            if filters["mitigation_forced"] is not None
            else "",
            "from_ts": _datetime_to_epoch(filters["from_dt"]),
            "to_ts": _datetime_to_epoch(filters["to_dt"]),
            "sort": filters["sort"],
            "limit": filters["limit"],
            "offset": filters["offset"],
        }
    else:
        filters_state = {
            "tenant": (raw_filters["tenant"] or "").strip(),
            "bot": (raw_filters["bot"] or "").strip(),
            "decision": (raw_filters["decision"] or "").strip(),
            "mitigation_forced": (raw_filters["mitigation_forced"] or "").strip(),
            "from_ts": _coerce_epoch(raw_filters["from_ts"]),
            "to_ts": _coerce_epoch(raw_filters["to_ts"]),
            "sort": "ts_desc",
            "limit": 50,
            "offset": 0,
        }

    rendered_items = [_render_adjudication_row(item) for item in items]

    current_limit = int(filters_state.get("limit", 50))
    current_offset = int(filters_state.get("offset", 0))
    current_sort = filters_state.get("sort", "ts_desc") or "ts_desc"

    visible_count = len(items)
    if total <= 0 and visible_count > 0:
        total = current_offset + visible_count
    range_start = 0 if total == 0 or visible_count == 0 else current_offset + 1
    if total == 0:
        range_end = current_offset + visible_count
    else:
        range_end = min(total, current_offset + visible_count)
    disable_next = total > 0 and current_offset + current_limit >= total

    filter_inputs = {
        "tenant": filters_state.get("tenant", ""),
        "bot": filters_state.get("bot", ""),
        "decision": filters_state.get("decision", ""),
        "mitigation_forced": filters_state.get("mitigation_forced", ""),
        "from_ts": _epoch_to_iso(filters_state.get("from_ts")),
        "to_ts": _epoch_to_iso(filters_state.get("to_ts")),
    }

    ndjson_params: Dict[str, str] = {}
    for key in ("tenant", "bot", "decision", "mitigation_forced"):
        value = filters_state.get(key)
        if value:
            ndjson_params[key] = str(value)
    for key in ("from_ts", "to_ts"):
        value = filters_state.get(key)
        if value not in (None, ""):
            ndjson_params[key] = str(value)
    sort_val = filters_state.get("sort")
    if sort_val:
        ndjson_params["sort"] = str(sort_val)
    ndjson_query = urlencode(ndjson_params)
    ndjson_url = "/admin/adjudications.ndjson" + (f"?{ndjson_query}" if ndjson_query else "")

    bootstrap_state = {
        "filters": filters_state,
        "items": items,
        "total": total,
        "error": error_message,
    }

    resp = templates.TemplateResponse(
        "adjudications.html",
        {
            "request": req,
            "filter_inputs": filter_inputs,
            "rendered_items": rendered_items,
            "current_limit": current_limit,
            "current_offset": current_offset,
            "current_sort": current_sort,
            "display_range": {"start": range_start, "end": range_end},
            "total_count": total,
            "disable_next": disable_next,
            "error_message": error_message,
            "ndjson_url": ndjson_url,
            "bootstrap_state": bootstrap_state,
        },
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
@router.get("/admin/webhooks", response_class=HTMLResponse)
def ui_webhooks(req: Request, _: None = Depends(require_auth)) -> HTMLResponse:
    csrf_token = _csrf_token()
    resp = templates.TemplateResponse(
        "webhooks.html",
        {
            "request": req,
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
            "lints": [],
        },
    )
    issue_csrf(resp, csrf_token)
    return resp


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------


def _require_ui_csrf(req: Request, token: str) -> None:
    cookie = req.cookies.get("ui_csrf", "")
    if not (
        cookie
        and token
        and _csrf_ok(token)
        and _csrf_ok(cookie)
        and hmac.compare_digest(cookie, token)
    ):
        raise HTTPException(status_code=400, detail="CSRF failed")


@router.post("/admin/ui/reload", response_class=PlainTextResponse)
def ui_reload(
    req: Request, csrf_token: str = Form(...), _: None = Depends(require_auth)
) -> PlainTextResponse:
    _require_ui_csrf(req, csrf_token)
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
    records = _decisions_mod().list_decisions(sort="ts_desc")[: max(int(n), 0)]
    for item in records:
        import json

        buf.write(json.dumps(item) + "\n")
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/x-ndjson",
        headers={"Content-Disposition": "attachment; filename=decisions.ndjson"},
    )


@router.post("/admin/ui/bindings/apply_golden", response_class=JSONResponse)
def ui_apply_golden(
    req: Request, payload: Dict[str, Any], _: None = Depends(require_auth)
) -> JSONResponse:
    token = str(payload.get("csrf_token", ""))
    _require_ui_csrf(req, token)

    tenant = str(payload.get("tenant", "")).strip()
    bot = str(payload.get("bot", "")).strip()
    if not tenant or not bot:
        raise HTTPException(status_code=400, detail="tenant and bot are required.")

    try:
        result = apply_golden_action({"tenant": tenant, "bot": bot})
    except HTTPException:
        raise
    except Exception as exc:  # pragma: no cover - unexpected failure
        raise HTTPException(status_code=500, detail=str(exc))

    try:
        bindings = list_bindings()
    except Exception:  # pragma: no cover - underlying store failure
        bindings = []

    if result.get("applied"):
        message = f"Golden Packs applied to {tenant}/{bot}."
        status = "success"
    else:
        message = "Already using Golden Packs."
        status = "info"

    return JSONResponse(
        {
            "message": message,
            "status": status,
            "applied": bool(result.get("applied")),
            "binding": result,
            "bindings": bindings,
        }
    )


@router.post("/admin/ui/bindings/apply_strict_secrets", response_class=JSONResponse)
def ui_apply_strict_secrets(
    req: Request, payload: Dict[str, Any], _: None = Depends(require_auth)
) -> JSONResponse:
    token = str(payload.get("csrf_token", ""))
    _require_ui_csrf(req, token)

    tenant = str(payload.get("tenant", "")).strip()
    bot = str(payload.get("bot", "")).strip()
    if not tenant or not bot:
        raise HTTPException(status_code=400, detail="tenant and bot are required.")

    try:
        result = apply_strict_action({"tenant": tenant, "bot": bot})
    except HTTPException:
        raise
    except Exception as exc:  # pragma: no cover - unexpected failure
        raise HTTPException(status_code=500, detail=str(exc))

    try:
        bindings = list_bindings()
    except Exception:  # pragma: no cover - underlying store failure
        bindings = []

    if result.get("applied"):
        message = f"Applied to {tenant}/{bot}."
        status = "success"
    else:
        message = "Already applied; refreshed caches."
        status = "info"

    return JSONResponse(
        {
            "message": message,
            "status": status,
            "applied": bool(result.get("applied")),
            "binding": result,
            "bindings": bindings,
        }
    )


@router.post("/admin/ui/bindings/apply_demo_defaults", response_class=JSONResponse)
def ui_apply_demo_defaults(
    req: Request, payload: Dict[str, Any], _: None = Depends(require_auth)
) -> JSONResponse:
    token = str(payload.get("csrf_token", ""))
    _require_ui_csrf(req, token)

    tenant = str(payload.get("tenant", "")).strip()
    bot = str(payload.get("bot", "")).strip()
    if not tenant or not bot:
        raise HTTPException(status_code=400, detail="tenant and bot are required.")

    try:
        result = apply_demo_action({"tenant": tenant, "bot": bot})
    except HTTPException:
        raise
    except Exception as exc:  # pragma: no cover - unexpected failure
        raise HTTPException(status_code=500, detail=str(exc))

    try:
        bindings = list_bindings()
    except Exception:  # pragma: no cover - underlying store failure
        bindings = []

    if result.get("applied"):
        message = f"Applied to {tenant}/{bot}."
        status = "success"
    else:
        message = "Already applied; refreshed caches."
        status = "info"

    return JSONResponse(
        {
            "message": message,
            "status": status,
            "applied": bool(result.get("applied")),
            "binding": result,
            "bindings": bindings,
        }
    )


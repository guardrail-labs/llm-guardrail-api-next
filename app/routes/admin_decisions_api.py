from __future__ import annotations

import importlib
import os
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Protocol, Tuple, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel
from starlette.templating import Jinja2Templates


def _load_require_admin():
    """
    Locate shared admin guard.
    Resolution:
      1) ADMIN_GUARD="module.subpath:callable" (or defaults to :require_admin)
      2) Known modules (in order):
         - app.routes.admin_rbac:require_admin
         - app.security.admin_auth:require_admin
         - app.routes.admin_common:require_admin
         - app.security.admin:require_admin
         - app.security.auth:require_admin
    """
    # Env override
    env = os.getenv("ADMIN_GUARD")
    if env:
        mod_name, _, fn_name = env.partition(":")
        fn_name = fn_name or "require_admin"
        try:
            mod = importlib.import_module(mod_name)
            fn = getattr(mod, fn_name, None)
            if callable(fn):
                return fn
        except Exception:
            pass

    candidates = (
        ("app.routes.admin_rbac", "require_admin"),
        ("app.security.admin_auth", "require_admin"),
        ("app.routes.admin_common", "require_admin"),
        ("app.security.admin", "require_admin"),
        ("app.security.auth", "require_admin"),
    )
    for mod_name, fn_name in candidates:
        try:
            mod = importlib.import_module(mod_name)
            fn = getattr(mod, fn_name, None)
            if callable(fn):
                return fn
        except Exception:
            continue
    return None


def _require_admin_dep(request: Request):
    """
    Enforcement policy:
      - If ADMIN_API_KEY / GUARDRAIL_ADMIN_KEY (or settings.admin.key) is configured,
        the request MUST provide the correct key (via X-Admin-Key header or ?admin_key=).
      - Additionally, if a repo-level require_admin guard exists, invoke it (it may raise).
      - If no key is configured and no guard is found, allow (dev-friendly default).
    """
    # Gather configured key from env or settings
    settings = getattr(request.app.state, "settings", None)
    admin_settings = getattr(settings, "admin", None)
    cfg_key = (
        os.getenv("ADMIN_API_KEY")
        or os.getenv("GUARDRAIL_ADMIN_KEY")
        or getattr(admin_settings, "key", None)
    )
    # Call repo guard if present (let it raise if unauthorized)
    guard = _load_require_admin()
    if callable(guard):
        guard(request)  # if it raises, FastAPI returns 401/403

    # If a key is configured, it is mandatory regardless of guard outcome
    if cfg_key:
        supplied = request.headers.get("X-Admin-Key") or request.query_params.get("admin_key")
        if str(supplied) != str(cfg_key):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Admin authentication required",
            )

    # No key configured and no guard raised: allow (dev)
    return None


router = APIRouter(dependencies=[Depends(_require_admin_dep)])
templates = Jinja2Templates(directory="app/ui/templates")


class DecisionItem(BaseModel):
    id: str
    ts: str
    tenant: str
    bot: str
    outcome: str
    policy_version: Optional[str] = None
    rule_id: Optional[str] = None
    incident_id: Optional[str] = None
    mode: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class DecisionPage(BaseModel):
    items: List[DecisionItem]
    page: int
    page_size: int
    has_more: bool
    total: Optional[int] = None


class DecisionProvider(Protocol):
    def __call__(
        self,
        since: Optional[datetime],
        tenant: Optional[str],
        bot: Optional[str],
        outcome: Optional[str],
        limit: int,
        offset: int,
    ) -> Tuple[List[Dict[str, Any]], Optional[int]]:
        ...

_provider: Optional[DecisionProvider] = None


def set_decision_provider(fn: DecisionProvider) -> None:
    global _provider
    _provider = fn


def _auto_detect_provider() -> Optional[DecisionProvider]:
    for mod_name in (
        "app.services.decisions",
        "app.services.decision_log",
        "app.observability.decisions",
    ):
        try:
            mod = __import__(mod_name, fromlist=["*"])
            for fn_name in ("query", "list", "search"):
                fn = getattr(mod, fn_name, None)
                if callable(fn):
                    def provider(
                        since: Optional[datetime],
                        tenant: Optional[str],
                        bot: Optional[str],
                        outcome: Optional[str],
                        limit: int,
                        offset: int,
                        _fn=fn,
                    ) -> Tuple[List[Dict[str, Any]], Optional[int]]:
                        res = _fn(
                            since=since,
                            tenant=tenant,
                            bot=bot,
                            outcome=outcome,
                            limit=limit,
                            offset=offset,
                        )
                        if isinstance(res, tuple) and len(res) == 2:
                            return cast(Tuple[List[Dict[str, Any]], Optional[int]], res)
                        items = list(cast(Iterable[Dict[str, Any]], res))
                        return items, None

                    return provider
        except Exception:
            continue
    return None


def _get_provider() -> DecisionProvider:
    global _provider
    if _provider is not None:
        return _provider
    detected = _auto_detect_provider()
    if detected is None:
        def empty_provider(
            since: Optional[datetime],
            tenant: Optional[str],
            bot: Optional[str],
            outcome: Optional[str],
            limit: int,
            offset: int,
        ) -> Tuple[List[Dict[str, Any]], Optional[int]]:
            return [], 0

        _provider = empty_provider
    else:
        _provider = detected
    return _provider


def _parse_since(since: Optional[str]) -> Optional[datetime]:
    if not since:
        return None
    try:
        dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _iso_utc(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _norm_item(d: Dict[str, Any]) -> DecisionItem:
    ts = d.get("ts")
    if isinstance(ts, datetime):
        ts_iso = _iso_utc(ts)
    elif isinstance(ts, str):
        ts_iso = _iso_utc(_parse_since(ts) or datetime.now(timezone.utc))
    else:
        ts_iso = _iso_utc(datetime.now(timezone.utc))
    return DecisionItem(
        id=str(d.get("id") or d.get("request_id") or d.get("incident_id") or ""),
        ts=ts_iso,
        tenant=str(d.get("tenant") or "unknown"),
        bot=str(d.get("bot") or "unknown"),
        outcome=str(d.get("outcome") or d.get("decision") or "unknown"),
        policy_version=d.get("policy_version"),
        rule_id=d.get("rule_id"),
        incident_id=d.get("incident_id"),
        mode=d.get("mode"),
        details=d.get("details"),
    )


@router.get("/admin/api/decisions", response_model=DecisionPage)
async def get_decisions(
    request: Request,
    since: Optional[str] = Query(None, description="ISO8601 timestamp (UTC)"),
    tenant: Optional[str] = Query(None),
    bot: Optional[str] = Query(None),
    outcome: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
) -> JSONResponse:
    prov = _get_provider()
    since_dt = _parse_since(since)
    offset = (page - 1) * page_size
    try:
        items_raw, total = prov(
            since=since_dt,
            tenant=tenant,
            bot=bot,
            outcome=outcome,
            limit=page_size,
            offset=offset,
        )
    except TypeError:
        items_raw, total = prov(since_dt, tenant, bot, outcome, page_size, offset)
    items = [_norm_item(x) for x in items_raw]
    if total is not None:
        has_more = (offset + len(items)) < total
    else:
        has_more = len(items) == page_size
    payload = DecisionPage(
        items=items,
        page=page,
        page_size=page_size,
        has_more=has_more,
        total=total,
    )
    return JSONResponse(payload.model_dump())


@router.get("/admin/decisions", response_class=HTMLResponse)
async def decisions_page(
    request: Request,
    since: Optional[str] = None,
    tenant: Optional[str] = None,
    bot: Optional[str] = None,
    outcome: Optional[str] = None,
    page: int = 1,
    page_size: int = 50,
) -> Response:
    accept = (request.headers.get("accept") or "").lower()
    wants_html = "text/html" in accept or "application/xhtml+xml" in accept
    if not wants_html:
        prov = _get_provider()
        since_dt = _parse_since(since)
        offset = (page - 1) * page_size
        items_raw, _ = prov(since_dt, tenant, bot, outcome, page_size, offset)
        return JSONResponse(items_raw)
    return templates.TemplateResponse(
        "decisions.html",
        {
            "request": request,
            "since": since or "",
            "tenant": tenant or "",
            "bot": bot or "",
            "outcome": outcome or "",
            "page": page,
            "page_size": page_size,
        },
    )

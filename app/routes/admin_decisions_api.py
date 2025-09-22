from __future__ import annotations

import csv
import importlib
import inspect
import io
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, Iterator, List, Literal, Optional, Tuple, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel
from starlette.templating import Jinja2Templates

from app.middleware.scope import require_effective_scope, set_effective_scope_headers
from app.security.rbac import RBACError, ensure_scope, require_viewer
from app.services.decisions_store import list_with_cursor
from app.utils.cursor import CursorError

SortKey = Literal["ts", "tenant", "bot", "outcome", "policy_version", "rule_id", "incident_id"]
SortDir = Literal["asc", "desc"]
SORT_KEYS: Tuple[SortKey, ...] = (
    "ts",
    "tenant",
    "bot",
    "outcome",
    "policy_version",
    "rule_id",
    "incident_id",
)
ProviderResult = Tuple[List[Dict[str, Any]], Optional[int]]
DecisionProvider = Callable[..., ProviderResult]


def _normalize_provider_result(result: Any) -> ProviderResult:
    if isinstance(result, tuple) and len(result) == 2:
        items_raw, total_raw = result
        items_list = list(cast(Iterable[Dict[str, Any]], items_raw))
        total_norm = cast(Optional[int], total_raw)
        return items_list, total_norm
    items_iter = list(cast(Iterable[Dict[str, Any]], result))
    return items_iter, None


def _call_decisions_provider(
    fn: Callable[..., Any],
    *,
    since: Optional[datetime],
    tenant: Optional[str],
    bot: Optional[str],
    outcome: Optional[str],
    request_id: Optional[str] = None,
    page: int,
    page_size: int,
    sort_key: Optional[str] = None,
    sort_dir: Optional[str] = None,
) -> ProviderResult:
    base: Dict[str, Any] = dict(since=since, tenant=tenant, bot=bot, outcome=outcome)
    if request_id is not None:
        base["request_id"] = request_id
    if sort_key is not None:
        base["sort_key"] = sort_key
    if sort_dir is not None:
        base["sort_dir"] = sort_dir

    try:
        sig = inspect.signature(fn)
        params = sig.parameters
        if all(param in params for param in ("page", "page_size")):
            return _normalize_provider_result(
                fn(page=page, page_size=page_size, **base)
            )
    except Exception:
        pass

    try:
        return _normalize_provider_result(fn(page=page, page_size=page_size, **base))
    except TypeError:
        limit = page_size
        offset = max((page - 1) * page_size, 0)
        try:
            return _normalize_provider_result(
                fn(limit=limit, offset=offset, **base)
            )
        except TypeError:
            try:
                return _normalize_provider_result(
                    fn(
                        since,
                        tenant,
                        bot,
                        outcome,
                        limit,
                        offset,
                        base.get("sort_key"),
                        base.get("sort_dir"),
                    )
                )
            except TypeError:
                return _normalize_provider_result(
                    fn(
                        since,
                        tenant,
                        bot,
                        outcome,
                        limit,
                        offset,
                    )
                )


def _wrap_decisions_provider(*functions: Callable[..., Any]) -> DecisionProvider:
    candidates = [*functions]
    if not candidates:
        raise ValueError("at least one provider function is required")

    def provider(
        since: Optional[datetime],
        tenant: Optional[str],
        bot: Optional[str],
        outcome: Optional[str],
        limit: int,
        offset: int,
        sort_key: SortKey = "ts",
        sort_dir: SortDir = "desc",
        _candidates=candidates,
        **extra: Any,
    ) -> ProviderResult:
        page_size = max(int(limit) if limit is not None else 0, 0) or 1
        page = max(int(offset) // page_size + 1, 1)
        last_exc: Optional[TypeError] = None
        request_id = cast(Optional[str], extra.get("request_id"))
        for idx, underlying in enumerate(list(_candidates)):
            try:
                result = _call_decisions_provider(
                    underlying,
                    since=since,
                    tenant=tenant,
                    bot=bot,
                    outcome=outcome,
                    request_id=request_id,
                    page=page,
                    page_size=page_size,
                    sort_key=sort_key,
                    sort_dir=sort_dir,
                )
            except TypeError as exc:
                last_exc = exc
                continue
            else:
                if idx != 0:
                    _candidates.insert(0, _candidates.pop(idx))
                return result
        if last_exc is not None:
            raise last_exc
        raise TypeError("no compatible decisions provider")

    return provider


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

    # Mark request as coming from the admin API path for downstream RBAC checks
    state_user = getattr(request.state, "admin_user", None)
    if not isinstance(state_user, dict):
        setattr(
            request.state,
            "admin_user",
            {"email": "admin@api-key", "name": "Admin API", "role": "admin"},
        )

    # No key configured and no guard raised: allow (dev)
    return None


log = logging.getLogger(__name__)

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
    page: Optional[int] = None
    page_size: Optional[int] = None
    has_more: Optional[bool] = None
    total: Optional[int] = None
    next_cursor: Optional[str] = None
    prev_cursor: Optional[str] = None
    limit: Optional[int] = None
    dir: Optional[Literal["next", "prev"]] = None


_provider: Optional[DecisionProvider] = None


def set_decision_provider(fn: DecisionProvider) -> None:
    global _provider
    _provider = _wrap_decisions_provider(fn)


def _auto_detect_provider() -> Optional[DecisionProvider]:
    for mod_name in (
        "app.services.decisions",
        "app.services.decision_log",
        "app.observability.decisions",
    ):
        try:
            mod = __import__(mod_name, fromlist=["*"])
            functions = [
                getattr(mod, fn_name, None)
                for fn_name in (
                    "list_decisions",
                    "query_decisions",
                    "query",
                    "list",
                    "search",
                )
            ]
            callables = [fn for fn in functions if callable(fn)]
            if callables:
                return _wrap_decisions_provider(*callables)
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
            sort_key: SortKey = "ts",
            sort_dir: SortDir = "desc",
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



def _list_decisions_offset_path(
    *,
    since: Optional[str],
    tenant: Optional[str],
    bot: Optional[str],
    outcome: Optional[str],
    request_id: Optional[str],
    page: int,
    page_size: int,
    sort: str,
    sort_dir: str,
    limit: int,
    offset: int,
) -> JSONResponse:
    prov = _get_provider()
    since_dt = _parse_since(since)
    sort_lower = (sort or "").lower()
    sort_key_safe: SortKey = cast(SortKey, sort_lower) if sort_lower in SORT_KEYS else "ts"
    sort_dir_safe: SortDir = "asc" if sort_dir == "asc" else "desc"
    def _filter_reqid(items: Iterable[Dict[str, Any]]) -> ProviderResult:
        materialized = list(items)
        if request_id is None:
            return materialized, None
        filtered = [
            item
            for item in materialized
            if (
                isinstance(item, dict) and item.get("request_id") == request_id
            )
            or getattr(item, "request_id", None) == request_id
        ]
        return filtered, len(filtered)

    try:
        items_raw, total = prov(
            since=since_dt,
            tenant=tenant,
            bot=bot,
            outcome=outcome,
            request_id=request_id,
            limit=page_size,
            offset=offset,
            sort_key=sort_key_safe,
            sort_dir=sort_dir_safe,
        )
    except TypeError:
        result: Optional[ProviderResult] = None
        if request_id is not None:
            try:
                result = prov(
                    since_dt,
                    tenant,
                    bot,
                    outcome,
                    request_id,
                    page_size,
                    offset,
                    sort_key_safe,
                    sort_dir_safe,
                )
            except TypeError:
                try:
                    result = prov(
                        since_dt,
                        tenant,
                        bot,
                        outcome,
                        request_id,
                        page_size,
                        offset,
                    )
                except TypeError:
                    result = None

        if result is None:
            try:
                items_raw, total = prov(
                    since_dt,
                    tenant,
                    bot,
                    outcome,
                    page_size,
                    offset,
                    sort_key_safe,
                    sort_dir_safe,
                )
                if request_id is not None:
                    items_raw, total = _filter_reqid(items_raw)
                result = (items_raw, total)
            except TypeError:
                try:
                    items_raw, total = prov(
                        since_dt,
                        tenant,
                        bot,
                        outcome,
                        page_size,
                        offset,
                    )
                    if request_id is not None:
                        items_raw, total = _filter_reqid(items_raw)
                    result = (items_raw, total)
                except TypeError as final_exc:
                    raise HTTPException(
                        status_code=500,
                        detail="decisions provider error",
                    ) from final_exc

        items_raw, total = result
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
        next_cursor=None,
        prev_cursor=None,
        limit=limit,
        dir="next",
    )
    return JSONResponse(payload.model_dump())


@router.get(
    "/admin/api/decisions",
    response_model=DecisionPage,
    tags=["admin-decisions"],
    summary="List decisions (cursor)",
    description=(
        "Cursor-paginated decisions ordered by (ts desc, id). Supports filters for tenant, "
        "bot, since (epoch ms), outcome, and request_id."
    ),
)
async def get_decisions(
    request: Request,
    response: Response,
    scope=Depends(require_effective_scope),
    since: Optional[str] = Query(
        None,
        description="Filter decisions since this ISO8601 timestamp (UTC)",
        examples=[{"summary": "Recent decisions", "value": "2024-01-01T00:00:00Z"}],
    ),
    tenant: Optional[str] = Query(
        None,
        description="Filter decisions for this tenant",
        examples=[{"summary": "Tenant filter", "value": "tenant-123"}],
    ),
    bot: Optional[str] = Query(
        None,
        description="Filter decisions for this bot",
        examples=[{"summary": "Bot filter", "value": "bot-alpha"}],
    ),
    outcome: Optional[str] = Query(
        None,
        description="Filter by outcome",
        examples=[{"summary": "Allow outcome", "value": "allow"}],
    ),
    request_id: Optional[str] = Query(
        None,
        description="Return decisions for a specific request ID",
        examples=[{"summary": "Specific request", "value": "req-123"}],
    ),
    page: int = Query(
        1,
        ge=1,
        description="1-based page number (ignored when limit/offset query params are provided)",
    ),
    page_size: int = Query(
        50,
        ge=1,
        le=500,
        description="Items per page when using page/page_size (overridden by limit/offset)",
    ),
    sort: str = "ts",
    sort_dir: Optional[str] = Query(None, alias="sort_dir"),
    limit: int = Query(
        50,
        ge=1,
        le=500,
        description="Maximum number of items to return when using cursor pagination",
        examples=[{"summary": "Custom page size", "value": 100}],
    ),
    cursor: Optional[str] = Query(
        None,
        description="Opaque cursor token from a previous response",
        examples=[{"summary": "Resume token", "value": "1704067200000:dec_42"}],
    ),
    page_dir: Literal["next", "prev"] = Query(
        "next",
        alias="cursor_dir",
        description="Direction relative to the provided cursor",
        examples=[{"summary": "Previous page", "value": "prev"}],
    ),
    offset: Optional[int] = Query(
        None,
        description="Offset to use with limit when cursor is not supplied",
        examples=[{"summary": "First page", "value": 0}],
    ),
) -> JSONResponse:
    eff_tenant, eff_bot = scope
    set_effective_scope_headers(response, eff_tenant, eff_bot)

    def _offset_response(**kwargs) -> JSONResponse:
        resp = _list_decisions_offset_path(**kwargs)
        set_effective_scope_headers(resp, eff_tenant, eff_bot)
        return resp

    query_dir_raw = request.query_params.get("dir")
    query_dir = query_dir_raw.lower() if query_dir_raw else None

    sort_dir_value = (sort_dir or "").lower() if sort_dir else None
    if not sort_dir_value and query_dir and query_dir not in {"next", "prev"}:
        sort_dir_value = query_dir
    if sort_dir_value not in {"asc", "desc"}:
        sort_dir_value = "desc"

    requested_page_size = max(int(page_size), 1)
    effective_limit = max(int(limit), 1)
    page_size_param = request.query_params.get("page_size")
    if page_size_param is not None:
        try:
            requested_page_size = max(int(page_size_param), 1)
        except ValueError:
            requested_page_size = max(int(page_size), 1)
    limit_param = request.query_params.get("limit")
    if limit_param is not None:
        try:
            effective_limit = max(int(limit_param), 1)
        except ValueError:
            effective_limit = max(int(limit), 1)
    effective_offset = (
        int(offset)
        if offset is not None
        else max((int(page) - 1) * requested_page_size, 0)
    )

    if cursor is None and query_dir and query_dir not in {"next", "prev"}:
        log.warning("Offset pagination is deprecated; prefer cursor.")
        return _offset_response(
            since=since,
            tenant=eff_tenant,
            bot=eff_bot,
            outcome=outcome,
            request_id=request_id,
            page=max(int(page), 1),
            page_size=requested_page_size,
            sort=sort,
            sort_dir=sort_dir_value,
            limit=requested_page_size,
            offset=effective_offset,
        )

    if offset is not None and cursor is None:
        log.warning("Offset pagination is deprecated; prefer cursor.")
        return _offset_response(
            since=since,
            tenant=eff_tenant,
            bot=eff_bot,
            outcome=outcome,
            request_id=request_id,
            page=max(int(page), 1),
            page_size=requested_page_size,
            sort=sort,
            sort_dir=sort_dir_value,
            limit=requested_page_size,
            offset=effective_offset,
        )

    pagination_dir = page_dir
    if cursor and query_dir:
        if query_dir not in {"next", "prev"}:
            raise HTTPException(
                status_code=400,
                detail="dir must be 'next' or 'prev' when using cursor pagination.",
            )
        pagination_dir = cast(Literal["next", "prev"], query_dir)

    since_ts_ms: Optional[int] = None
    if since:
        parsed_since = _parse_since(since)
        if parsed_since is not None:
            since_ts_ms = int(parsed_since.timestamp() * 1000)

    try:
        items_raw, next_cursor, prev_cursor = list_with_cursor(
            tenant=eff_tenant,
            bot=eff_bot,
            limit=effective_limit,
            cursor=cursor,
            dir=pagination_dir,
            since_ts_ms=since_ts_ms,
            outcome=outcome,
            request_id=request_id,
        )
    except CursorError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        log.warning("Cursor pagination unavailable (%s); falling back to offset path.", exc)
        return _offset_response(
            since=since,
            tenant=eff_tenant,
            bot=eff_bot,
            outcome=outcome,
            request_id=request_id,
            page=max(int(page), 1),
            page_size=requested_page_size,
            sort=sort,
            sort_dir=sort_dir_value,
            limit=requested_page_size,
            offset=effective_offset,
        )

    items = [_norm_item(x) for x in items_raw]
    has_more = bool(next_cursor if pagination_dir == "next" else prev_cursor)
    payload = DecisionPage(
        items=items,
        page=None,
        page_size=effective_limit,
        has_more=has_more,
        total=None,
        next_cursor=next_cursor,
        prev_cursor=prev_cursor,
        limit=effective_limit,
        dir=pagination_dir,
    )
    resp = JSONResponse(payload.model_dump())
    set_effective_scope_headers(resp, eff_tenant, eff_bot)
    return resp


@router.get("/admin/decisions", response_class=HTMLResponse)
async def decisions_page(
    request: Request,
    since: Optional[str] = None,
    tenant: Optional[str] = None,
    bot: Optional[str] = None,
    outcome: Optional[str] = None,
    page: int = Query(
        1,
        ge=1,
        description="1-based page number (ignored when limit/offset query params are provided)",
    ),
    page_size: int = Query(
        50,
        ge=1,
        le=500,
        description="Items per page when using page/page_size (overridden by limit/offset)",
    ),
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


CSV_FIELDS = (
    "ts",
    "tenant",
    "bot",
    "outcome",
    "policy_version",
    "rule_id",
    "incident_id",
    "mode",
    "id",
    "details",  # JSON-encoded blob in CSV
)


def _paged_items(
    provider,
    since_dt,
    tenant: str | None,
    bot: str | None,
    outcome: str | None,
    batch: int = 1000,
) -> Iterator[DecisionItem]:
    offset = 0
    while True:
        try:
            chunk, _total = provider(
                since=since_dt,
                tenant=tenant,
                bot=bot,
                outcome=outcome,
                limit=batch,
                offset=offset,
            )
        except TypeError:
            chunk, _total = provider(since_dt, tenant, bot, outcome, batch, offset)
        if not chunk:
            break
        for raw in chunk:
            yield _norm_item(raw)
        if len(chunk) < batch:
            break
        offset += batch


def _stream_csv(
    provider,
    since_dt,
    tenant: str | None,
    bot: str | None,
    outcome: str | None,
    batch: int = 1000,
) -> Iterable[bytes]:
    # header
    header_buf = io.StringIO()
    writer = csv.writer(header_buf)
    writer.writerow(CSV_FIELDS)
    yield header_buf.getvalue().encode("utf-8", errors="replace")

    # rows
    for it in _paged_items(provider, since_dt, tenant, bot, outcome, batch):
        row_buf = io.StringIO()
        w = csv.writer(row_buf)
        details_str = json.dumps(it.details or {}, separators=(",", ":"), ensure_ascii=False)
        w.writerow(
            (
                it.ts,
                it.tenant,
                it.bot,
                it.outcome,
                it.policy_version or "",
                it.rule_id or "",
                it.incident_id or "",
                it.mode or "",
                it.id,
                details_str,
            )
        )
        yield row_buf.getvalue().encode("utf-8", errors="replace")


def _stream_jsonl(
    provider,
    since_dt,
    tenant: str | None,
    bot: str | None,
    outcome: str | None,
    batch: int = 1000,
) -> Iterable[bytes]:
    for it in _paged_items(provider, since_dt, tenant, bot, outcome, batch):
        line = (
            json.dumps(
                {
                    "id": it.id,
                    "ts": it.ts,
                    "tenant": it.tenant,
                    "bot": it.bot,
                    "outcome": it.outcome,
                    "policy_version": it.policy_version,
                    "rule_id": it.rule_id,
                    "incident_id": it.incident_id,
                    "mode": it.mode,
                    "details": it.details,
                },
                separators=(",", ":"),
                ensure_ascii=False,
            )
            + "\n"
        )
        yield line.encode("utf-8", errors="replace")


@router.get("/admin/api/decisions/export")
async def export_decisions(
    request: Request,
    format: str = Query("csv", pattern="^(csv|jsonl)$"),
    since: Optional[str] = Query(None, description="ISO8601 timestamp (UTC)"),
    tenant: Optional[str] = Query(None),
    bot: Optional[str] = Query(None),
    outcome: Optional[str] = Query(None),
    batch: int = Query(1000, ge=100, le=10000),
):
    """
    Stream decisions as CSV or JSONL. Same filters as the list API.
    """

    user = require_viewer(request)
    try:
        ensure_scope(user, tenant=tenant, bot=bot)
    except RBACError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    prov = _get_provider()
    since_dt = _parse_since(since)

    if format == "jsonl":
        filename = "decisions.jsonl"
        media_type = "application/x-ndjson"
        body_iter = _stream_jsonl(prov, since_dt, tenant, bot, outcome, batch)
    else:
        filename = "decisions.csv"
        media_type = "text/csv"
        body_iter = _stream_csv(prov, since_dt, tenant, bot, outcome, batch)

    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return StreamingResponse(body_iter, media_type=media_type, headers=headers)

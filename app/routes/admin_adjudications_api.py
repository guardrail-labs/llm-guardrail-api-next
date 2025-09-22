from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response

from app.middleware.scope import (
    as_iterable_scope,
    require_effective_scope,
    set_effective_scope_headers,
)
from app.observability import adjudication_log as log
from app.utils.cursor import CursorError

try:
    from app.routes import admin_decisions_api as _admin_decisions
except Exception as exc:  # pragma: no cover - surface import error when used
    raise ImportError("admin dependencies unavailable") from exc


router = APIRouter(
    prefix="/admin/api",
    tags=["admin-adjudications"],
    dependencies=[Depends(_admin_decisions._require_admin_dep)],
)


@router.get(
    "/adjudications",
    summary="List adjudications (cursor)",
    description=(
        "Cursor-paginated adjudications ordered by (ts desc, id). Supports filters for tenant, "
        "bot, since (epoch ms), outcome, rule_id, and request_id."
    ),
)
def list_adjudications(
    request: Request,
    response: Response,
    scope=Depends(require_effective_scope),
    limit: int = Query(
        50,
        ge=1,
        le=500,
        description="Maximum number of adjudications to include in the response",
        examples=[{"summary": "Custom page size", "value": 100}],
    ),
    cursor: Optional[str] = Query(
        None,
        description="Opaque cursor token from a previous response",
        examples=[{"summary": "Resume token", "value": "1704067200000:adj_7"}],
    ),
    dir: Literal["next", "prev"] = Query(
        "next",
        description="Direction relative to the provided cursor",
        examples=[{"summary": "Previous page", "value": "prev"}],
    ),
    tenant: Optional[str] = Query(
        None,
        description="Filter adjudications for this tenant",
        examples=[{"summary": "Tenant filter", "value": "tenant-123"}],
    ),
    bot: Optional[str] = Query(
        None,
        description="Filter adjudications for this bot",
        examples=[{"summary": "Bot filter", "value": "bot-alpha"}],
    ),
    since: Optional[int] = Query(
        None,
        description="Return adjudications at or after this epoch millisecond timestamp",
        examples=[{"summary": "Recent adjudications", "value": 1704067200000}],
    ),
    outcome: Optional[str] = Query(
        None,
        description="Filter by adjudication outcome",
        examples=[{"summary": "Allow outcome", "value": "allow"}],
    ),
    rule_id: Optional[str] = Query(
        None,
        description="Filter by rule identifier",
        examples=[{"summary": "Rule identifier", "value": "rule-1"}],
    ),
    request_id: Optional[str] = Query(
        None,
        description="Return adjudications for a specific request ID",
        examples=[{"summary": "Specific request", "value": "req-123"}],
    ),
):
    eff_tenant, eff_bot = scope
    set_effective_scope_headers(response, eff_tenant, eff_bot)

    eff_tenant_seq = as_iterable_scope(eff_tenant)
    eff_bot_seq = as_iterable_scope(eff_bot)
    try:
        items, next_cur, prev_cur = log.list_with_cursor(
            limit=limit,
            cursor=cursor,
            dir=dir,
            tenant=eff_tenant_seq,
            bot=eff_bot_seq,
            since_ts_ms=since,
            outcome=outcome,
            rule_id=rule_id,
            request_id=request_id,
        )
    except CursorError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "items": [item.__dict__ for item in items],
        "next_cursor": next_cur,
        "prev_cursor": prev_cur,
        "limit": limit,
        "dir": dir,
        "tenant": tenant,
        "bot": bot,
        "since": since,
        "outcome": outcome,
        "rule_id": rule_id,
        "request_id": request_id,
    }

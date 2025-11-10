from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from app.middleware.scope import require_effective_scope, set_effective_scope_headers
from app.observability import adjudication_log as log
from app.security.rbac import require_viewer
from app.utils.cursor import CursorError

router = APIRouter(prefix="/observability", tags=["observability"])


@router.get(
    "/clarifications",
    summary="List clarify decisions",
    description=(
        "Return recent clarify decisions scoped to the caller's tenant/bot permissions. "
        "Supports cursor pagination consistent with other observability endpoints."
    ),
)
def list_clarifications(
    response: Response,
    user: Dict[str, Any] = Depends(require_viewer),
    tenant: Optional[str] = Query(
        None,
        description="Filter clarifications for a specific tenant. Scoped tokens must provide this filter.",
    ),
    bot: Optional[str] = Query(
        None,
        description="Optional bot filter. Scoped tokens must provide this when their bot scope is limited.",
    ),
    limit: int = Query(
        50,
        ge=1,
        le=500,
        description="Maximum number of clarifications to return in a single response.",
    ),
    cursor: Optional[str] = Query(
        None,
        description="Opaque pagination cursor from a previous response.",
    ),
    dir: Literal["next", "prev"] = Query(
        "next",
        description="Pagination direction relative to the provided cursor.",
    ),
    since: Optional[int] = Query(
        None,
        description="Return clarifications at or after this epoch millisecond timestamp.",
    ),
) -> Dict[str, Any]:
    """List clarification adjudications with strict tenant scoping."""

    eff_tenant, eff_bot = require_effective_scope(
        user=user,
        tenant=tenant,
        bot=bot,
        metric_endpoint="observability_clarifications",
    )
    set_effective_scope_headers(response, eff_tenant, eff_bot)

    try:
        records, next_cursor, prev_cursor = log.list_with_cursor(
            tenant=eff_tenant,
            bot=eff_bot,
            limit=limit,
            cursor=cursor,
            dir=dir,
            since_ts_ms=since,
            outcome="clarify",
        )
    except CursorError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    items: List[Dict[str, Any]] = []
    for record in records:
        if hasattr(record, "to_dict"):
            payload = record.to_dict()
        else:
            payload = dict(vars(record))
        items.append(payload)

    return {
        "items": items,
        "next_cursor": next_cursor,
        "prev_cursor": prev_cursor,
        "limit": limit,
        "dir": dir,
        "tenant": tenant,
        "bot": bot,
        "since": since,
    }

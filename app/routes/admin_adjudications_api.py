from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

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


@router.get("/adjudications")
def list_adjudications(
    limit: int = Query(50, ge=1, le=500),
    cursor: Optional[str] = Query(None),
    dir: Literal["next", "prev"] = Query("next"),
    tenant: Optional[str] = Query(None),
    bot: Optional[str] = Query(None),
    since: Optional[int] = Query(None),
    outcome: Optional[str] = Query(None),
    rule_id: Optional[str] = Query(None),
    request_id: Optional[str] = Query(None),
):
    try:
        items, next_cur, prev_cur = log.list_with_cursor(
            limit=limit,
            cursor=cursor,
            dir=dir,
            tenant=tenant,
            bot=bot,
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

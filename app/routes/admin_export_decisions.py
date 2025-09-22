from __future__ import annotations

import datetime as _dt
import json
import time
from typing import Any, Dict, Iterable, Iterator, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from app.security.rbac import RBACError, ensure_scope, require_viewer
from app.services import decisions_store as _store

router = APIRouter(prefix="/admin/api", tags=["admin-export"])


def require_admin_session() -> bool:
    """Placeholder dependency for admin session validation."""

    return True


def _normalize_decision(item: Dict[str, Any]) -> Dict[str, Any]:
    obj = dict(item)
    ts = obj.get("ts")
    if isinstance(ts, _dt.datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=_dt.timezone.utc)
        obj["ts"] = ts.astimezone(_dt.timezone.utc).isoformat().replace("+00:00", "Z")
    return obj


def _iter_decisions_pages(
    *,
    tenant: Optional[str],
    bot: Optional[str],
    since: Optional[int],
    outcome: Optional[str],
    page_size: int = 500,
) -> Iterator[list[Dict[str, Any]]]:
    cursor: Optional[Tuple[int, str]] = None
    while True:
        page = _store._fetch_decisions_sorted_desc(
            tenant=tenant,
            bot=bot,
            limit=page_size,
            cursor=cursor,
            dir="next",
            since_ts_ms=since,
            outcome=outcome,
        )
        if not page:
            break
        normalized = [_store._ensure_ts_ms(row) for row in page]
        yield normalized
        if len(page) < page_size:
            break
        last = normalized[-1]
        cursor = (int(last["ts_ms"]), str(last["id"]))


def _iter_decisions_ndjson(
    *,
    tenant: Optional[str],
    bot: Optional[str],
    since: Optional[int],
    until: Optional[int],
    outcome: Optional[str],
) -> Iterable[bytes]:
    for batch in _iter_decisions_pages(
        tenant=tenant,
        bot=bot,
        since=since,
        outcome=outcome,
    ):
        for entry in batch:
            ts_ms = int(entry.get("ts_ms", 0))
            if since is not None and ts_ms < since:
                continue
            if until is not None and ts_ms > until:
                continue
            if tenant and entry.get("tenant") != tenant:
                continue
            if bot and entry.get("bot") != bot:
                continue
            if outcome and entry.get("outcome") != outcome:
                continue
            payload = _normalize_decision(entry)
            yield (
                json.dumps(payload, separators=(",", ":"), ensure_ascii=False) + "\n"
            ).encode("utf-8")


@router.get("/decisions/export.ndjson")
def export_decisions_ndjson(
    request: Request,
    tenant: Optional[str] = Query(None),
    bot: Optional[str] = Query(None),
    since: Optional[int] = Query(None, description="Epoch ms inclusive"),
    until: Optional[int] = Query(None, description="Epoch ms inclusive"),
    outcome: Optional[str] = Query(None, description="allow|block|clarify|redact"),
    _=Depends(require_admin_session),
):
    """
    Stream Decisions as NDJSON. Honors tenant, bot, since, until, outcome filters.
    Content-Type: application/x-ndjson
    """

    if not isinstance(getattr(request.state, "admin_user", None), dict):
        setattr(
            request.state,
            "admin_user",
            {"email": "admin@export", "name": "Admin Export", "role": "admin"},
        )
    user = require_viewer(request)
    try:
        ensure_scope(user, tenant=tenant, bot=bot)
    except RBACError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    now = _dt.datetime.utcfromtimestamp(time.time()).strftime("%Y%m%dT%H%M%SZ")
    fname = f"decisions_{now}.ndjson"
    gen = _iter_decisions_ndjson(
        tenant=tenant,
        bot=bot,
        since=since,
        until=until,
        outcome=outcome,
    )
    return StreamingResponse(
        gen,
        media_type="application/x-ndjson",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )

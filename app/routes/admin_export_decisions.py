from __future__ import annotations

import datetime as _dt
import json
import time
from typing import Any, Dict, Iterable, Iterator, Optional, Tuple

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import StreamingResponse

from app.middleware.scope import (
    as_single_scope,
    require_effective_scope,
    set_effective_scope_headers,
)
from app.security.rbac import require_viewer
from app.services import decisions_store as _store

router = APIRouter(prefix="/admin/api", tags=["admin-export"])


def _export_scope_dependency(
    request: Request,
    tenant: Optional[str] = Query(None),
    bot: Optional[str] = Query(None),
):
    if not isinstance(getattr(request.state, "admin_user", None), dict):
        setattr(
            request.state,
            "admin_user",
            {"email": "admin@export", "name": "Admin Export", "role": "admin"},
        )
    user = require_viewer(request)
    return require_effective_scope(user=user, tenant=tenant, bot=bot)


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
    _request: Request,
    response: Response,
    scope=Depends(_export_scope_dependency),
    since: Optional[int] = Query(None, description="Epoch ms inclusive"),
    until: Optional[int] = Query(None, description="Epoch ms inclusive"),
    outcome: Optional[str] = Query(None, description="allow|block|clarify|redact"),
):
    """
    Stream Decisions as NDJSON. Honors tenant, bot, since, until, outcome filters.
    Content-Type: application/x-ndjson
    """

    eff_tenant, eff_bot = scope
    set_effective_scope_headers(response, eff_tenant, eff_bot)
    tenant_single = as_single_scope(eff_tenant, field="tenant")
    bot_single = as_single_scope(eff_bot, field="bot")

    now = _dt.datetime.utcfromtimestamp(time.time()).strftime("%Y%m%dT%H%M%SZ")
    fname = f"decisions_{now}.ndjson"
    gen = _iter_decisions_ndjson(
        tenant=tenant_single,
        bot=bot_single,
        since=since,
        until=until,
        outcome=outcome,
    )
    stream = StreamingResponse(
        gen,
        media_type="application/x-ndjson",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )
    set_effective_scope_headers(stream, eff_tenant, eff_bot)
    return stream

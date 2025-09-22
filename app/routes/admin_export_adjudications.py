from __future__ import annotations

import datetime as _dt
import json
import time
from typing import Iterable, Optional

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import StreamingResponse

from app.middleware.scope import (
    as_single_scope,
    require_effective_scope,
    set_effective_scope_headers,
)
from app.observability import adjudication_log as _log
from app.security.rbac import require_viewer

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


def _ms_to_dt(value: Optional[int]) -> Optional[_dt.datetime]:
    if value is None:
        return None
    try:
        return _dt.datetime.fromtimestamp(value / 1000.0, tz=_dt.timezone.utc)
    except Exception:
        return None


def _iter_adjudications_ndjson(
    *,
    tenant: Optional[str],
    bot: Optional[str],
    since: Optional[int],
    until: Optional[int],
    outcome: Optional[str],
    rule_id: Optional[str],
    request_id: Optional[str],
) -> Iterable[bytes]:
    start_dt = _ms_to_dt(since)
    end_dt = None
    if until is not None:
        end_dt = _ms_to_dt(until + 1)
    for record in _log.iter_records(
        start=start_dt,
        end=end_dt,
        tenant=tenant,
        bot=bot,
        request_id=request_id,
        rule_id=rule_id,
        decision=outcome,
        sort="ts_desc",
    ):
        if hasattr(record, "to_dict"):
            payload = record.to_dict()
        else:
            payload = dict(vars(record))
        yield (
            json.dumps(payload, separators=(",", ":"), ensure_ascii=False) + "\n"
        ).encode("utf-8")


@router.get("/adjudications/export.ndjson")
def export_adjudications_ndjson(
    _request: Request,
    response: Response,
    scope=Depends(_export_scope_dependency),
    since: Optional[int] = Query(None, description="Epoch ms inclusive"),
    until: Optional[int] = Query(None, description="Epoch ms inclusive"),
    outcome: Optional[str] = Query(None, description="allow|block|clarify|redact"),
    rule_id: Optional[str] = Query(None),
    request_id: Optional[str] = Query(None),
):
    """
    Stream Adjudications as NDJSON. Honors tenant, bot, since, until, outcome,
    rule_id, and request_id filters. Content-Type: application/x-ndjson
    """

    eff_tenant, eff_bot = scope
    set_effective_scope_headers(response, eff_tenant, eff_bot)
    tenant_single = as_single_scope(eff_tenant, field="tenant")
    bot_single = as_single_scope(eff_bot, field="bot")

    now = _dt.datetime.utcfromtimestamp(time.time()).strftime("%Y%m%dT%H%M%SZ")
    fname = f"adjudications_{now}.ndjson"
    gen = _iter_adjudications_ndjson(
        tenant=tenant_single,
        bot=bot_single,
        since=since,
        until=until,
        outcome=outcome,
        rule_id=rule_id,
        request_id=request_id,
    )
    stream = StreamingResponse(
        gen,
        media_type="application/x-ndjson",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )
    set_effective_scope_headers(stream, eff_tenant, eff_bot)
    return stream

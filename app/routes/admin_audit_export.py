from __future__ import annotations

import datetime
import json
import time
from typing import Any, Dict, Iterable, Optional

from fastapi import APIRouter, Query, Request
from fastapi.responses import StreamingResponse

from app.middleware.scope import require_effective_scope, set_effective_scope_headers
from app.observability import admin_audit
from app.security.rbac import require_viewer

router = APIRouter(prefix="/admin/api", tags=["admin-audit"])


def _ensure_audit_user(request: Request) -> None:
    if not isinstance(getattr(request.state, "admin_user", None), dict):
        setattr(
            request.state,
            "admin_user",
            {"email": "admin@audit", "name": "Admin Audit", "role": "admin"},
        )


def _matches(
    obj: Dict[str, Any],
    *,
    since: Optional[int],
    until: Optional[int],
    tenant: Optional[str],
    bot: Optional[str],
    action: Optional[str],
    outcome: Optional[str],
) -> bool:
    try:
        ts_val = int(obj.get("ts_ms", 0))
    except Exception:
        ts_val = 0
    if since is not None and ts_val < since:
        return False
    if until is not None and ts_val > until:
        return False
    if tenant and obj.get("tenant") != tenant:
        return False
    if bot and obj.get("bot") != bot:
        return False
    if action and obj.get("action") != action:
        return False
    if outcome and obj.get("outcome") != outcome:
        return False
    return True


def _iter_ndjson(
    *,
    since: Optional[int],
    until: Optional[int],
    tenant: Optional[str],
    bot: Optional[str],
    action: Optional[str],
    outcome: Optional[str],
) -> Iterable[bytes]:
    for obj in admin_audit.iter_events():
        if _matches(
            obj,
            since=since,
            until=until,
            tenant=tenant,
            bot=bot,
            action=action,
            outcome=outcome,
        ):
            payload = json.dumps(obj, separators=(",", ":"), ensure_ascii=False) + "\n"
            yield payload.encode("utf-8")


@router.get("/audit/export.ndjson")
def export_audit_ndjson(
    request: Request,
    since: Optional[int] = Query(None, description="Epoch ms inclusive"),
    until: Optional[int] = Query(None, description="Epoch ms inclusive"),
    tenant: Optional[str] = Query(None),
    bot: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    outcome: Optional[str] = Query(None, pattern="^(ok|error)$"),
):
    """Stream admin audit events as NDJSON."""

    _ensure_audit_user(request)
    user = require_viewer(request)
    eff_tenant, eff_bot = require_effective_scope(
        user=user, tenant=tenant, bot=bot
    )
    timestamp = datetime.datetime.utcfromtimestamp(time.time()).strftime("%Y%m%dT%H%M%SZ")
    filename = f"admin_audit_{timestamp}.ndjson"
    generator = _iter_ndjson(
        since=since,
        until=until,
        tenant=eff_tenant,
        bot=eff_bot,
        action=action,
        outcome=outcome,
    )
    response = StreamingResponse(
        generator,
        media_type="application/x-ndjson",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
    set_effective_scope_headers(response, eff_tenant, eff_bot)
    return response

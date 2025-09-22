from __future__ import annotations

import datetime as _dt
import json
import time
from collections import Counter
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from starlette.background import BackgroundTask

from app.observability import adjudication_log as adj_log, admin_audit as audit_log
from app.routes.admin_mitigation import require_csrf
from app.security.rbac import require_admin
from app.services import decisions_bus

router = APIRouter(prefix="/admin/api/data", tags=["admin-data"])

_ALLOWED_KINDS = {"decisions", "adjudications", "audit"}


def _now_fname() -> str:
    return _dt.datetime.utcfromtimestamp(time.time()).strftime("%Y%m%dT%H%M%SZ")


def _normalize_kinds(raw: Sequence[str]) -> List[str]:
    kinds: List[str] = []
    for item in raw:
        normalized = item.strip().lower()
        if not normalized:
            continue
        if normalized not in _ALLOWED_KINDS:
            raise HTTPException(status_code=400, detail=f"Unsupported kind: {item}")
        if normalized not in kinds:
            kinds.append(normalized)
    if not kinds:
        raise HTTPException(status_code=400, detail="At least one kind must be requested")
    return kinds


def _extract_ts_ms(obj: Mapping[str, Any]) -> int:
    raw = obj.get("ts_ms")
    if raw is not None:
        try:
            return int(float(raw))
        except Exception:
            pass
    raw_ts = obj.get("ts")
    if isinstance(raw_ts, (int, float)):
        value = float(raw_ts)
        if value > 1_000_000_000_000:
            return int(value)
        return int(value * 1000)
    if isinstance(raw_ts, str):
        if raw_ts.isdigit():
            value = float(raw_ts)
            if value > 1_000_000_000_000:
                return int(value)
            return int(value * 1000)
        try:
            dt = _dt.datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
            return int(dt.timestamp() * 1000)
        except Exception:
            return 0
    return 0


def _match_common(
    obj: Mapping[str, Any],
    *,
    tenant: Optional[str],
    bot: Optional[str],
    since: Optional[int],
    until: Optional[int],
) -> bool:
    ts_ms = _extract_ts_ms(obj)
    if since is not None and ts_ms < since:
        return False
    if until is not None and ts_ms > until:
        return False
    if tenant and obj.get("tenant") != tenant:
        return False
    if bot and obj.get("bot") != bot:
        return False
    return True


def _iter_records(
    kinds: Sequence[str],
    *,
    tenant: Optional[str],
    bot: Optional[str],
    since: Optional[int],
    until: Optional[int],
) -> Iterator[Dict[str, Any]]:
    if "decisions" in kinds:
        for record in decisions_bus.iter_all():
            if _match_common(record, tenant=tenant, bot=bot, since=since, until=until):
                yield {"kind": "decisions", **record}
    if "adjudications" in kinds:
        for record in adj_log.iter_all():
            if _match_common(record, tenant=tenant, bot=bot, since=since, until=until):
                yield {"kind": "adjudications", **record}
    if "audit" in kinds:
        for record in audit_log.iter_events(since=since, until=until, tenant=tenant, bot=bot):
            payload = dict(record)
            payload.setdefault("ts_ms", _extract_ts_ms(payload))
            yield {"kind": "audit", **payload}


def _emit_ndjson(objs: Iterable[Dict[str, Any]], counter: Counter) -> Iterator[bytes]:
    for obj in objs:
        kind = obj.get("kind")
        if isinstance(kind, str):
            counter[kind] += 1
        yield (json.dumps(obj, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


@router.get("/export.ndjson")
def export_ndjson(
    request: Request,
    kinds: str = Query(..., description="Comma-separated kinds: decisions,adjudications,audit"),
    tenant: Optional[str] = Query(None),
    bot: Optional[str] = Query(None),
    since: Optional[int] = Query(None, description="Epoch milliseconds inclusive"),
    until: Optional[int] = Query(None, description="Epoch milliseconds inclusive"),
    user: Dict[str, Any] = Depends(require_admin),
):
    parts = [part for part in kinds.split(",")]
    try:
        normalized = _normalize_kinds(parts)
    except HTTPException as exc:
        audit_log.record(
            action="data_export",
            actor_email=(user or {}).get("email") if isinstance(user, dict) else None,
            actor_role=(user or {}).get("role") if isinstance(user, dict) else None,
            tenant=tenant,
            bot=bot,
            outcome="error",
            meta={"reason": str(exc.detail), "kinds": parts},
        )
        raise

    counts: Counter[str] = Counter()
    iterator = _iter_records(
        normalized,
        tenant=tenant,
        bot=bot,
        since=since,
        until=until,
    )
    filename = f"data_export_{_now_fname()}.ndjson"

    def _audit_done() -> None:
        audit_log.record(
            action="data_export",
            actor_email=(user or {}).get("email") if isinstance(user, dict) else None,
            actor_role=(user or {}).get("role") if isinstance(user, dict) else None,
            tenant=tenant,
            bot=bot,
            outcome="ok",
            meta={
                "kinds": list(normalized),
                "since": since,
                "until": until,
                "counts": dict(counts),
                "path": str(request.url.path),
            },
        )

    stream = _emit_ndjson(iterator, counts)
    background = BackgroundTask(_audit_done)
    return StreamingResponse(
        stream,
        media_type="application/x-ndjson",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        background=background,
    )


class DeleteRequest(BaseModel):
    kinds: List[str]
    tenant: Optional[str] = None
    bot: Optional[str] = None
    before_ts_ms: int = Field(
        ..., ge=0, description="Delete records with ts_ms strictly before this value"
    )
    csrf_token: Optional[str] = None


class DeleteResponse(BaseModel):
    deleted: Dict[str, int]


def _ensure_csrf_token(header_token: Optional[str], payload: DeleteRequest) -> str:
    body_token = payload.csrf_token or ""
    token = (header_token or body_token or "").strip()
    if not token or not token.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="CSRF token required")
    return token


@router.post("/delete", response_model=DeleteResponse)
def delete_data(
    payload: DeleteRequest,
    csrf_header: Optional[str] = Header(None, alias="X-CSRF-Token"),
    user: Dict[str, Any] = Depends(require_admin),
    __: None = Depends(require_csrf),
) -> DeleteResponse:
    try:
        normalized = _normalize_kinds(payload.kinds)
    except HTTPException as exc:
        audit_log.record(
            action="data_delete",
            actor_email=(user or {}).get("email") if isinstance(user, dict) else None,
            actor_role=(user or {}).get("role") if isinstance(user, dict) else None,
            tenant=payload.tenant,
            bot=payload.bot,
            outcome="error",
            meta={"reason": str(exc.detail), "kinds": payload.kinds},
        )
        raise

    try:
        _ensure_csrf_token(csrf_header, payload)
    except HTTPException:
        audit_log.record(
            action="data_delete",
            actor_email=(user or {}).get("email") if isinstance(user, dict) else None,
            actor_role=(user or {}).get("role") if isinstance(user, dict) else None,
            tenant=payload.tenant,
            bot=payload.bot,
            outcome="error",
            meta={"reason": "csrf_required", "kinds": list(normalized)},
        )
        raise

    counts = {"decisions": 0, "adjudications": 0, "audit": 0}
    if "decisions" in normalized:
        counts["decisions"] = decisions_bus.delete_where(
            tenant=payload.tenant,
            bot=payload.bot,
            before_ts_ms=payload.before_ts_ms,
        )
    if "adjudications" in normalized:
        counts["adjudications"] = adj_log.delete_where(
            tenant=payload.tenant,
            bot=payload.bot,
            before_ts_ms=payload.before_ts_ms,
        )
    if "audit" in normalized:
        counts["audit"] = audit_log.delete_where(
            tenant=payload.tenant,
            bot=payload.bot,
            before_ts_ms=payload.before_ts_ms,
        )

    audit_log.record(
        action="data_delete",
        actor_email=(user or {}).get("email") if isinstance(user, dict) else None,
        actor_role=(user or {}).get("role") if isinstance(user, dict) else None,
        tenant=payload.tenant,
        bot=payload.bot,
        outcome="ok",
        meta={
            "kinds": list(normalized),
            "before_ts_ms": int(payload.before_ts_ms),
            "counts": dict(counts),
        },
    )
    return DeleteResponse(deleted=counts)

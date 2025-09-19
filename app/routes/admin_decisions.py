from __future__ import annotations

import csv
import io
import json
import queue
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple, TypedDict

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse

from app.routes.admin_ui import require_auth
from app.services.decisions_bus import (
    iter_decisions,
    list_decisions,
    snapshot,
    subscribe,
    unsubscribe,
)

router = APIRouter(prefix="/admin", tags=["admin-decisions"])

_VALID_DECISIONS = {"allow", "block", "clarify", "redact", "deny"}
_VALID_SORT = {"ts_desc", "ts_asc"}


class _Filters(TypedDict):
    tenant: Optional[str]
    bot: Optional[str]
    rule_id: Optional[str]
    decision: Optional[str]
    from_ts: Optional[int]
    to_ts: Optional[int]
    limit: int
    offset: int
    sort: str


def _safe_int(s: Optional[str]) -> Optional[int]:
    if s is None:
        return None
    try:
        return int(s)
    except Exception:
        return None


def _parse_params(req: Request) -> Tuple[Dict[str, Any], int, bool]:
    q = req.query_params
    filters: Dict[str, Any] = {
        "tenant": q.get("tenant") or None,
        "bot": q.get("bot") or None,
        "family": q.get("family") or None,
        "mode": q.get("mode") or None,
        "rule_id": q.get("rule_id") or None,
        "since": _safe_int(q.get("since")),
    }
    limit = _safe_int(q.get("limit")) or 200
    if limit < 1:
        limit = 1
    if limit > 2000:
        limit = 2000
    sse_flag = (q.get("sse") or "").lower() in ("1", "true", "yes", "on")
    return filters, limit, sse_flag


def _match(evt: Dict[str, Any], f: Dict[str, Any]) -> bool:
    tenant = f.get("tenant")
    if tenant and evt.get("tenant") != tenant:
        return False
    bot = f.get("bot")
    if bot and evt.get("bot") != bot:
        return False
    family = f.get("family")
    if family and evt.get("family") != family:
        return False
    mode = f.get("mode")
    if mode and evt.get("mode") != mode:
        return False
    since = f.get("since")
    if since is not None and int(evt.get("ts", 0)) < int(since):
        return False
    rule_id = f.get("rule_id")
    if rule_id:
        rids = evt.get("rule_ids") or []
        if rule_id not in rids:
            return False
    return True


def _json_error(message: str, status_code: int = 400) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status_code)


def _normalize_optional(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _parse_int(raw: Optional[str], *, field: str, default: Optional[int] = None) -> Optional[int]:
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw.strip())
    except Exception:
        raise ValueError(f"{field} must be an integer")
    return value


def _parse_limit(raw: Optional[str]) -> int:
    value = _parse_int(raw, field="limit", default=50)
    assert value is not None
    if value < 1:
        raise ValueError("limit must be >= 1")
    if value > 500:
        value = 500
    return value


def _parse_offset(raw: Optional[str]) -> int:
    value = _parse_int(raw, field="offset", default=0)
    assert value is not None
    if value < 0:
        raise ValueError("offset must be >= 0")
    return value


def _parse_epoch(raw: Optional[str], name: str) -> Optional[int]:
    value = _parse_int(raw, field=name, default=None)
    if value is not None and value < 0:
        raise ValueError(f"{name} must be >= 0")
    return value


def _parse_sort(raw: Optional[str]) -> str:
    if raw is None or not raw.strip():
        return "ts_desc"
    value = raw.strip()
    if value not in _VALID_SORT:
        raise ValueError("sort must be one of ts_desc or ts_asc")
    return value


def _parse_filters(
    *,
    tenant: Optional[str],
    bot: Optional[str],
    rule_id: Optional[str],
    decision: Optional[str],
    from_ts: Optional[str],
    to_ts: Optional[str],
    limit: Optional[str],
    offset: Optional[str],
    sort: Optional[str],
) -> Tuple[Optional[_Filters], Optional[JSONResponse]]:
    try:
        decision_norm = _normalize_optional(decision)
        if decision_norm and decision_norm not in _VALID_DECISIONS:
            raise ValueError("invalid decision")

        from_val = _parse_epoch(from_ts, "from_ts")
        to_val = _parse_epoch(to_ts, "to_ts")
        if from_val is not None and to_val is not None and to_val <= from_val:
            raise ValueError("to_ts must be greater than from_ts")

        limit_val = _parse_limit(limit)
        offset_val = _parse_offset(offset)
        sort_val = _parse_sort(sort)

        filters: _Filters = {
            "tenant": _normalize_optional(tenant),
            "bot": _normalize_optional(bot),
            "rule_id": _normalize_optional(rule_id),
            "decision": decision_norm,
            "from_ts": from_val,
            "to_ts": to_val,
            "limit": limit_val,
            "offset": offset_val,
            "sort": sort_val,
        }
        return filters, None
    except ValueError as exc:
        return None, _json_error(str(exc))


def _parse_filters_no_pagination(
    *,
    tenant: Optional[str],
    bot: Optional[str],
    rule_id: Optional[str],
    decision: Optional[str],
    from_ts: Optional[str],
    to_ts: Optional[str],
    sort: Optional[str],
) -> Tuple[Optional[_Filters], Optional[JSONResponse]]:
    filters, error = _parse_filters(
        tenant=tenant,
        bot=bot,
        rule_id=rule_id,
        decision=decision,
        from_ts=from_ts,
        to_ts=to_ts,
        limit=None,
        offset=None,
        sort=sort,
    )
    if filters is not None:
        filters["limit"] = 0
        filters["offset"] = 0
    return filters, error


def _serialize_items(items: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [dict(item) for item in items]


@router.get("/decisions")
def get_decisions(
    tenant: Optional[str] = Query(default=None),
    bot: Optional[str] = Query(default=None),
    rule_id: Optional[str] = Query(default=None),
    decision: Optional[str] = Query(default=None),
    from_ts: Optional[str] = Query(default=None),
    to_ts: Optional[str] = Query(default=None),
    limit: Optional[str] = Query(default=None),
    offset: Optional[str] = Query(default=None),
    sort: Optional[str] = Query(default=None),
    _: None = Depends(require_auth),
) -> JSONResponse:
    filters, error = _parse_filters(
        tenant=tenant,
        bot=bot,
        rule_id=rule_id,
        decision=decision,
        from_ts=from_ts,
        to_ts=to_ts,
        limit=limit,
        offset=offset,
        sort=sort,
    )
    if error:
        return error
    assert filters is not None

    records = list_decisions(
        tenant=filters["tenant"],
        bot=filters["bot"],
        rule_id=filters["rule_id"],
        decision=filters["decision"],
        from_ts=filters["from_ts"],
        to_ts=filters["to_ts"],
        sort=filters["sort"],
    )
    total = len(records)
    start = filters["offset"]
    end = start + filters["limit"]
    items = records[start:end]

    payload = {
        "items": _serialize_items(items),
        "total": total,
        "limit": filters["limit"],
        "offset": filters["offset"],
        "sort": filters["sort"],
    }
    return JSONResponse(payload)


def _ndjson_stream(filters: _Filters) -> Iterator[str]:
    for item in iter_decisions(
        tenant=filters["tenant"],
        bot=filters["bot"],
        rule_id=filters["rule_id"],
        decision=filters["decision"],
        from_ts=filters["from_ts"],
        to_ts=filters["to_ts"],
        sort=filters["sort"],
    ):
        yield json.dumps(item, separators=(",", ":"), ensure_ascii=False) + "\n"


@router.get("/decisions.ndjson")
def export_decisions_ndjson(
    tenant: Optional[str] = Query(default=None),
    bot: Optional[str] = Query(default=None),
    rule_id: Optional[str] = Query(default=None),
    decision: Optional[str] = Query(default=None),
    from_ts: Optional[str] = Query(default=None),
    to_ts: Optional[str] = Query(default=None),
    sort: Optional[str] = Query(default=None),
    _: None = Depends(require_auth),
) -> StreamingResponse:
    filters, error = _parse_filters_no_pagination(
        tenant=tenant,
        bot=bot,
        rule_id=rule_id,
        decision=decision,
        from_ts=from_ts,
        to_ts=to_ts,
        sort=sort,
    )
    if error:
        return error  # type: ignore[return-value]
    assert filters is not None

    stream = _ndjson_stream(filters)
    return StreamingResponse(stream, media_type="application/x-ndjson")


@router.get("/decisions/export.csv")
def export_decisions_csv(
    req: Request, _: None = Depends(require_auth)
) -> PlainTextResponse:
    filters, limit, sse_flag = _parse_params(req)  # noqa: F841
    events = [e for e in reversed(snapshot()) if _match(e, filters)][:limit]

    out = io.StringIO()
    headers: List[str] = [
        "ts",
        "incident_id",
        "request_id",
        "tenant",
        "bot",
        "family",
        "mode",
        "status",
        "endpoint",
        "rule_ids",
        "policy_version",
        "shadow_action",
        "shadow_rule_ids",
        "latency_ms",
    ]
    w = csv.DictWriter(out, fieldnames=headers)
    w.writeheader()
    for e in events:
        row = dict(e)
        row["rule_ids"] = ",".join(e.get("rule_ids") or [])
        row["shadow_rule_ids"] = ",".join(e.get("shadow_rule_ids") or [])
        w.writerow(row)
    return PlainTextResponse(out.getvalue(), media_type="text/csv")


@router.get("/decisions/stream")
def stream_decisions(req: Request, _: None = Depends(require_auth)) -> StreamingResponse:
    filters, limit, sse_flag = _parse_params(req)  # noqa: F841
    sub = subscribe()

    def _sse():
        # initial snapshot (newest first → present oldest of slice first)
        snap = [e for e in reversed(snapshot()) if _match(e, filters)][:limit]
        for e in reversed(snap):
            yield b"event: init\n"
            yield b"data: " + json.dumps(e).encode("utf-8") + b"\n\n"

        # live events
        try:
            while True:
                try:
                    evt = sub.get(timeout=15.0)  # keep-alive window
                except queue.Empty:
                    yield b": keep-alive\n\n"
                    continue

                if _match(evt, filters):
                    yield b"data: " + json.dumps(evt).encode("utf-8") + b"\n\n"
        finally:
            unsubscribe(sub)

    return StreamingResponse(_sse(), media_type="text/event-stream")

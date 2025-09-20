from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, Iterator, Optional, Tuple, TypedDict

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse, StreamingResponse

from app.observability import adjudication_log

try:
    from app.routes import admin_decisions_api as _admin_decisions
except Exception as exc:  # pragma: no cover - surface import error when used
    raise ImportError("admin dependencies unavailable") from exc


router = APIRouter(prefix="/admin", dependencies=[Depends(_admin_decisions._require_admin_dep)])

_VALID_DECISIONS = {"allow", "block", "clarify", "redact"}
_VALID_MITIGATIONS = {"block", "clarify", "redact"}
_VALID_SORT = {"ts_desc", "ts_asc"}


class _Filters(TypedDict):
    tenant: Optional[str]
    bot: Optional[str]
    provider: Optional[str]
    request_id: Optional[str]
    rule_id: Optional[str]
    decision: Optional[str]
    mitigation_forced: Optional[str]
    from_dt: Optional[datetime]
    to_dt: Optional[datetime]
    limit: int
    offset: int
    sort: str


def _serialize_record(record: adjudication_log.AdjudicationRecord) -> Dict[str, object]:
    data = record.to_dict()
    rule_id = getattr(record, "rule_id", None)
    if rule_id is not None:
        try:
            data["rule_id"] = str(rule_id)
        except Exception:
            data["rule_id"] = rule_id
    return data


def _json_error(message: str, status_code: int = 400) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status_code)


def _normalize_optional(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _parse_epoch_seconds(raw: Optional[str], name: str) -> Optional[datetime]:
    if raw is None:
        return None
    stripped = raw.strip()
    if not stripped:
        return None
    try:
        seconds = int(stripped)
    except Exception:
        raise ValueError(f"{name} must be an integer")
    return datetime.fromtimestamp(seconds, tz=timezone.utc)


def _parse_iso_timestamp(raw: Optional[str], name: str) -> Optional[datetime]:
    if raw is None:
        return None
    stripped = raw.strip()
    if not stripped:
        return None
    parsed = adjudication_log._parse_ts(stripped)
    if parsed is None:
        raise ValueError(f"{name} must be an ISO 8601 timestamp")
    return parsed


def _parse_limit(raw: Optional[str]) -> int:
    if raw is None or not str(raw).strip():
        value = 50
    else:
        try:
            value = int(str(raw).strip())
        except Exception:
            raise ValueError("limit must be an integer")
    if value < 1:
        raise ValueError("limit must be >= 1")
    if value > 500:
        value = 500
    return value


def _parse_offset(raw: Optional[str]) -> int:
    if raw is None or not str(raw).strip():
        return 0
    try:
        value = int(str(raw).strip())
    except Exception:
        raise ValueError("offset must be an integer")
    if value < 0:
        raise ValueError("offset must be >= 0")
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
    provider: Optional[str],
    request_id: Optional[str],
    rule_id: Optional[str],
    decision: Optional[str],
    mitigation_forced: Optional[str],
    start: Optional[str],
    end: Optional[str],
    from_ts: Optional[str],
    to_ts: Optional[str],
    limit: Optional[str],
    offset: Optional[str],
    sort: Optional[str],
) -> Tuple[Optional[_Filters], Optional[JSONResponse]]:
    try:
        decision_val = _normalize_optional(decision)
        if decision_val and decision_val not in _VALID_DECISIONS:
            raise ValueError("invalid decision")

        rule_id_val = _normalize_optional(rule_id)

        if mitigation_forced is None:
            mitigation_val: Optional[str] = None
        else:
            stripped = mitigation_forced.strip()
            if stripped == "":
                mitigation_val = ""
            else:
                if stripped not in _VALID_MITIGATIONS:
                    raise ValueError("invalid mitigation_forced")
                mitigation_val = stripped

        from_dt = _parse_epoch_seconds(from_ts, "from_ts")
        to_dt = _parse_epoch_seconds(to_ts, "to_ts")
        start_dt = _parse_iso_timestamp(start, "start")
        end_dt = _parse_iso_timestamp(end, "end")
        if from_dt is None:
            from_dt = start_dt
        if to_dt is None and end_dt is not None:
            to_dt = end_dt + timedelta(microseconds=1)

        limit_val = _parse_limit(limit)
        offset_val = _parse_offset(offset)
        sort_val = _parse_sort(sort)

        filters: _Filters = {
            "tenant": _normalize_optional(tenant),
            "bot": _normalize_optional(bot),
            "provider": _normalize_optional(provider),
            "request_id": _normalize_optional(request_id),
            "rule_id": rule_id_val,
            "decision": decision_val,
            "mitigation_forced": mitigation_val,
            "from_dt": from_dt,
            "to_dt": to_dt,
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
    provider: Optional[str],
    request_id: Optional[str],
    rule_id: Optional[str],
    decision: Optional[str],
    mitigation_forced: Optional[str],
    start: Optional[str],
    end: Optional[str],
    from_ts: Optional[str],
    to_ts: Optional[str],
    sort: Optional[str],
) -> Tuple[Optional[_Filters], Optional[JSONResponse]]:
    filters, error = _parse_filters(
        tenant=tenant,
        bot=bot,
        provider=provider,
        request_id=request_id,
        rule_id=rule_id,
        decision=decision,
        mitigation_forced=mitigation_forced,
        start=start,
        end=end,
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


@router.get("/adjudications")
async def list_adjudications(
    tenant: Optional[str] = Query(default=None),
    bot: Optional[str] = Query(default=None),
    provider: Optional[str] = Query(default=None),
    request_id: Optional[str] = Query(default=None),
    rule_id: Optional[str] = Query(default=None),
    decision: Optional[str] = Query(default=None),
    mitigation_forced: Optional[str] = Query(default=None),
    start: Optional[str] = Query(default=None),
    end: Optional[str] = Query(default=None),
    from_ts: Optional[str] = Query(default=None),
    to_ts: Optional[str] = Query(default=None),
    limit: Optional[str] = Query(default=None),
    offset: Optional[str] = Query(default=None),
    sort: Optional[str] = Query(default=None),
) -> JSONResponse:
    filters, error = _parse_filters(
        tenant=tenant,
        bot=bot,
        provider=provider,
        request_id=request_id,
        rule_id=rule_id,
        decision=decision,
        mitigation_forced=mitigation_forced,
        start=start,
        end=end,
        from_ts=from_ts,
        to_ts=to_ts,
        limit=limit,
        offset=offset,
        sort=sort,
    )
    if error:
        return error
    assert filters is not None

    records, total = adjudication_log.paged_query(
        start=filters["from_dt"],
        end=filters["to_dt"],
        tenant=filters["tenant"],
        bot=filters["bot"],
        provider=filters["provider"],
        request_id=filters["request_id"],
        rule_id=filters["rule_id"],
        decision=filters["decision"],
        mitigation_forced=filters["mitigation_forced"],
        limit=filters["limit"],
        offset=filters["offset"],
        sort=filters["sort"],
    )
    payload = {
        "items": [_serialize_record(rec) for rec in records],
        "total": total,
        "limit": filters["limit"],
        "offset": filters["offset"],
        "sort": filters["sort"],
    }
    return JSONResponse(payload)


def _ndjson_stream(filters: _Filters) -> Iterator[str]:
    yield from adjudication_log.stream(
        start=filters["from_dt"],
        end=filters["to_dt"],
        tenant=filters["tenant"],
        bot=filters["bot"],
        provider=filters["provider"],
        request_id=filters["request_id"],
        rule_id=filters["rule_id"],
        decision=filters["decision"],
        mitigation_forced=filters["mitigation_forced"],
        limit=None,
        sort=filters["sort"],
    )


@router.get("/adjudications.ndjson")
async def export_adjudications(
    tenant: Optional[str] = Query(default=None),
    bot: Optional[str] = Query(default=None),
    provider: Optional[str] = Query(default=None),
    request_id: Optional[str] = Query(default=None),
    rule_id: Optional[str] = Query(default=None),
    decision: Optional[str] = Query(default=None),
    mitigation_forced: Optional[str] = Query(default=None),
    start: Optional[str] = Query(default=None),
    end: Optional[str] = Query(default=None),
    from_ts: Optional[str] = Query(default=None),
    to_ts: Optional[str] = Query(default=None),
    sort: Optional[str] = Query(default=None),
) -> StreamingResponse:
    filters, error = _parse_filters_no_pagination(
        tenant=tenant,
        bot=bot,
        provider=provider,
        request_id=request_id,
        rule_id=rule_id,
        decision=decision,
        mitigation_forced=mitigation_forced,
        start=start,
        end=end,
        from_ts=from_ts,
        to_ts=to_ts,
        sort=sort,
    )
    if error:
        return error  # type: ignore[return-value]
    assert filters is not None

    stream = _ndjson_stream(filters)
    return StreamingResponse(stream, media_type="application/x-ndjson")


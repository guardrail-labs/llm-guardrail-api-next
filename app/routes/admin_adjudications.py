from __future__ import annotations

from typing import Dict, Iterator, Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse, StreamingResponse

from app.observability import adjudication_log

try:
    from app.routes import admin_decisions_api as _admin_decisions
except Exception as exc:  # pragma: no cover - surface import error when used
    raise ImportError("admin dependencies unavailable") from exc


router = APIRouter(prefix="/admin", dependencies=[Depends(_admin_decisions._require_admin_dep)])


def _serialize_record(record: adjudication_log.AdjudicationRecord) -> Dict[str, object]:
    return record.to_dict()


@router.get("/adjudications")
async def list_adjudications(
    start: Optional[str] = Query(default=None),
    end: Optional[str] = Query(default=None),
    tenant: Optional[str] = Query(default=None),
    bot: Optional[str] = Query(default=None),
    provider: Optional[str] = Query(default=None),
    request_id: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1),
) -> JSONResponse:
    records = adjudication_log.query(
        start=start,
        end=end,
        tenant=tenant,
        bot=bot,
        provider=provider,
        request_id=request_id,
        limit=limit,
    )
    payload = {"items": [_serialize_record(rec) for rec in records]}
    return JSONResponse(payload)


def _ndjson_stream(
    *,
    start: Optional[str] = None,
    end: Optional[str] = None,
    tenant: Optional[str] = None,
    bot: Optional[str] = None,
    provider: Optional[str] = None,
    request_id: Optional[str] = None,
    limit: int = 100,
) -> Iterator[str]:
    yield from adjudication_log.stream(
        start=start,
        end=end,
        tenant=tenant,
        bot=bot,
        provider=provider,
        request_id=request_id,
        limit=limit,
    )


@router.get("/adjudications/export.ndjson")
async def export_adjudications(
    start: Optional[str] = Query(default=None),
    end: Optional[str] = Query(default=None),
    tenant: Optional[str] = Query(default=None),
    bot: Optional[str] = Query(default=None),
    provider: Optional[str] = Query(default=None),
    request_id: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1),
) -> StreamingResponse:
    stream = _ndjson_stream(
        start=start,
        end=end,
        tenant=tenant,
        bot=bot,
        provider=provider,
        request_id=request_id,
        limit=limit,
    )
    return StreamingResponse(stream, media_type="application/x-ndjson")

from __future__ import annotations

import csv
import io
import json
from typing import Any, Dict, Iterator

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse

from app.routes.admin_ui import require_auth
from app.services.decisions_bus import snapshot, subscribe, unsubscribe
from app.services.decisions_filter import match

router = APIRouter(prefix="/admin", tags=["admin-decisions"])


def _parse_params(req: Request) -> tuple[dict[str, Any], int, bool]:
    q = req.query_params
    limit_raw = q.get("limit")
    try:
        limit = int(limit_raw) if limit_raw is not None else 200
    except Exception:
        limit = 200
    limit = max(1, min(2000, limit))
    filters: dict[str, Any] = {
        "tenant": q.get("tenant") or None,
        "bot": q.get("bot") or None,
        "family": q.get("family") or None,
        "mode": q.get("mode") or None,
        "rule_id": q.get("rule_id") or None,
        "since": int(q.get("since")) if q.get("since") else None,
    }
    once = (q.get("once") or "").strip().lower() in {"1", "true", "yes", "on"}
    return filters, limit, once


def _filtered_snapshot(filters: dict[str, Any], limit: int) -> list[Dict[str, Any]]:
    events = [evt for evt in reversed(list(snapshot())) if match(evt, **filters)]
    return events[:limit]


@router.get("/decisions")
def get_decisions(req: Request, _: None = Depends(require_auth)) -> JSONResponse:
    filters, limit, _ = _parse_params(req)
    events = _filtered_snapshot(filters, limit)
    return JSONResponse(events)


@router.get("/decisions/export.csv")
def export_decisions_csv(req: Request, _: None = Depends(require_auth)) -> PlainTextResponse:
    filters, limit, _ = _parse_params(req)
    events = _filtered_snapshot(filters, limit)
    out = io.StringIO()
    writer = csv.DictWriter(
        out,
        fieldnames=[
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
            "latency_ms",
        ],
    )
    writer.writeheader()
    for evt in events:
        row = dict(evt)
        rule_ids = evt.get("rule_ids") or []
        row["rule_ids"] = ",".join(str(rid) for rid in rule_ids if str(rid))
        writer.writerow(row)
    csv_text = out.getvalue()
    return PlainTextResponse(
        csv_text,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=decisions.csv"},
    )


@router.get("/decisions/stream")
def stream_decisions(req: Request, _: None = Depends(require_auth)) -> StreamingResponse:
    filters, limit, once = _parse_params(req)
    subscription = subscribe()

    def _stream() -> Iterator[bytes]:
        try:
            yield b":ok\n\n"
            snapshot_events = _filtered_snapshot(filters, limit)
            for evt in reversed(snapshot_events):
                payload = json.dumps(evt, ensure_ascii=False)
                yield f"event:init\ndata:{payload}\n\n".encode("utf-8")
            if once:
                return

            for evt in subscription:
                if match(evt, **filters):
                    payload = json.dumps(evt, ensure_ascii=False)
                    yield f"data:{payload}\n\n".encode("utf-8")
        finally:
            unsubscribe(subscription)

    headers = {
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
    }
    return StreamingResponse(_stream(), media_type="text/event-stream", headers=headers)

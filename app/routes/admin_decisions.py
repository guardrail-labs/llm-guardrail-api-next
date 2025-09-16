from __future__ import annotations

import csv
import io
import json
import queue
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse

from app.routes.admin_ui import require_auth
from app.services.decisions_bus import snapshot, subscribe, unsubscribe

router = APIRouter(prefix="/admin", tags=["admin-decisions"])


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
    sse = (q.get("sse") or "").lower() in ("1", "true", "yes", "on")
    return filters, limit, sse


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


@router.get("/decisions")
def get_decisions(req: Request, _: None = Depends(require_auth)) -> JSONResponse:
    filters, limit, _ = _parse_params(req)
    events = [e for e in reversed(snapshot()) if _match(e, filters)]
    return JSONResponse(events[:limit])


@router.get("/decisions/export.csv")
def export_decisions_csv(
    req: Request, _: None = Depends(require_auth)
) -> PlainTextResponse:
    filters, limit, _ = _parse_params(req)
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
        "latency_ms",
    ]
    w = csv.DictWriter(out, fieldnames=headers)
    w.writeheader()
    for e in events:
        row = dict(e)
        row["rule_ids"] = ",".join(e.get("rule_ids") or [])
        w.writerow(row)
    return PlainTextResponse(out.getvalue(), media_type="text/csv")


@router.get("/decisions/stream")
def stream_decisions(req: Request, _: None = Depends(require_auth)) -> StreamingResponse:
    filters, limit, _ = _parse_params(req)
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

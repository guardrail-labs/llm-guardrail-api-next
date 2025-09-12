# app/routes/system.py
# Summary (PR-Q): Adds /live and /ready endpoints for orchestrators.
# - /live: always 200 OK.
# - /ready: 503 until startup delay elapses (HEALTH_READY_DELAY_MS), then 200.
# - No impact to existing APIs; router is auto-included by main.py loader.

from __future__ import annotations

import asyncio
import os

from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()

# Readiness state
_ready_event: asyncio.Event = asyncio.Event()


def _read_delay_ms() -> int:
    raw = os.getenv("HEALTH_READY_DELAY_MS", "").strip()
    if not raw:
        return 0
    try:
        # accept ints/floats like "1500" or "1500.0"
        ms = int(float(raw))
        return ms if ms > 0 else 0
    except Exception:
        return 0


@router.on_event("startup")
async def _mark_ready_after_delay() -> None:
    delay_ms = _read_delay_ms()
    if delay_ms > 0:
        await asyncio.sleep(delay_ms / 1000.0)
    _ready_event.set()


@router.get("/live")
async def live() -> JSONResponse:
    return JSONResponse({"status": "ok", "ok": True})


@router.get("/ready")
async def ready() -> JSONResponse:
    if not _ready_event.is_set():
        return JSONResponse({"status": "starting", "ok": False}, status_code=503)
    return JSONResponse({"status": "ok", "ok": True})

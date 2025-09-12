# app/routes/system.py
# Summary (PR-U): Liveness/Readiness with graceful shutdown.
# - /live: always 200.
# - /ready: 200 once startup delay elapses; returns 503 during shutdown/drain.
# - Controlled by:
#     HEALTH_READY_DELAY_MS   (default 0)
#     HEALTH_DRAIN_DELAY_MS   (default 0) - optional sleep during shutdown.
# - Includes tiny test-only helpers to simulate drain toggling.

from __future__ import annotations

import asyncio
import os

from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()

_ready_event: asyncio.Event = asyncio.Event()
_draining: bool = False  # set during shutdown (and by test helper)


def _read_ms(name: str, default: int = 0) -> int:
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        ms = int(float(raw))
        return ms if ms > 0 else 0
    except Exception:
        return default


def _is_ready() -> bool:
    # Ready when startup completed and not draining.
    return _ready_event.is_set() and not _draining


@router.on_event("startup")
async def _mark_ready_after_delay() -> None:
    delay_ms = _read_ms("HEALTH_READY_DELAY_MS", 0)
    if delay_ms > 0:
        await asyncio.sleep(delay_ms / 1000.0)
    _ready_event.set()


@router.on_event("shutdown")
async def _flip_not_ready_then_drain() -> None:
    # Flip /ready to 503 as early as possible, then optionally wait so
    # orchestrators can stop routing traffic before process exit.
    global _draining
    _draining = True
    _ready_event.clear()
    drain_ms = _read_ms("HEALTH_DRAIN_DELAY_MS", 0)
    if drain_ms > 0:
        await asyncio.sleep(drain_ms / 1000.0)


@router.get("/live")
async def live() -> JSONResponse:
    return JSONResponse({"status": "ok", "ok": True})


@router.get("/ready")
async def ready() -> JSONResponse:
    if not _is_ready():
        return JSONResponse({"status": "starting", "ok": False}, status_code=503)
    return JSONResponse({"status": "ok", "ok": True})


# -------- Test helpers (no runtime effect) --------
# These are intentionally module-level (not exported via router) so tests
# can import and toggle readiness/drain without requiring lifecycle hooks.

def _enter_draining_for_tests() -> None:  # pragma: no cover - used in tests
    global _draining
    _draining = True
    _ready_event.clear()


def _reset_readiness_for_tests() -> None:  # pragma: no cover - used in tests
    global _draining
    _draining = False
    _ready_event.set()

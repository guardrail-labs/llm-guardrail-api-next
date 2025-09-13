# app/routes/system.py
# Summary (PR-W): Liveness/Readiness with optional verifier probe.
# - /live: always 200.
# - /ready: 200 once startup delay elapses AND (if enabled) probe passes.
# - During shutdown: flips to 503 (see PR-U).
# - Probe checks required env vars are present (cheap, no external calls).
#   Controlled by:
#     HEALTH_READY_DELAY_MS           (default 0)
#     HEALTH_DRAIN_DELAY_MS           (default 0)
#     PROBE_VERIFIER_ENABLED          (default 0 -> disabled)
#     PROBE_VERIFIER_REQUIRED_ENVS    (default "OPENAI_API_KEY")
#     PROBE_VERIFIER_INTERVAL_MS      (default 30000; 0 => only at startup)

from __future__ import annotations

import asyncio
import os
from typing import Optional

from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()

_ready_event: asyncio.Event = asyncio.Event()
_draining: bool = False  # set during shutdown (and by test helper)
_probe_task: Optional[asyncio.Task[None]] = None
_probe_ok: bool = True  # default true when probe is disabled


def _read_ms(name: str, default: int = 0) -> int:
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        ms = int(float(raw))
        return ms if ms > 0 else 0
    except Exception:
        return default


def _probe_enabled() -> bool:
    return (os.getenv("PROBE_VERIFIER_ENABLED", "") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _probe_required_envs() -> list[str]:
    raw = os.getenv("PROBE_VERIFIER_REQUIRED_ENVS", "OPENAI_API_KEY") or ""
    return [x.strip() for x in raw.split(",") if x.strip()]


def _probe_interval_ms() -> int:
    return _read_ms("PROBE_VERIFIER_INTERVAL_MS", 30000)


def _is_ready() -> bool:
    # Ready when startup completed, not draining, and probe (if enabled) is OK.
    if not _ready_event.is_set() or _draining:
        return False
    if _probe_enabled():
        return _probe_ok
    return True


async def _run_probe_once() -> None:
    """Cheap probe: are all required env vars present and non-empty?"""
    global _probe_ok
    if not _probe_enabled():
        _probe_ok = True
        return
    required = _probe_required_envs()
    ok = True
    for k in required:
        v = os.getenv(k, "")
        if not (v and v.strip()):
            ok = False
            break
    _probe_ok = ok


async def _probe_loop() -> None:
    try:
        interval_ms = _probe_interval_ms()
        # First run (in case env changed after startup delay)
        await _run_probe_once()
        while interval_ms > 0:
            await asyncio.sleep(interval_ms / 1000.0)
            await _run_probe_once()
    except asyncio.CancelledError:  # pragma: no cover
        pass


@router.on_event("startup")
async def _mark_ready_after_delay() -> None:
    delay_ms = _read_ms("HEALTH_READY_DELAY_MS", 0)
    if delay_ms > 0:
        await asyncio.sleep(delay_ms / 1000.0)

    # Initialize probe status and optionally start background loop
    await _run_probe_once()
    if _probe_enabled() and _probe_interval_ms() > 0:
        global _probe_task
        _probe_task = asyncio.create_task(_probe_loop())

    _ready_event.set()


@router.on_event("shutdown")
async def _flip_not_ready_then_drain() -> None:
    global _draining, _probe_task
    _draining = True
    _ready_event.clear()
    if _probe_task is not None:
        _probe_task.cancel()
        _probe_task = None
    drain_ms = _read_ms("HEALTH_DRAIN_DELAY_MS", 0)
    if drain_ms > 0:
        await asyncio.sleep(drain_ms / 1000.0)


@router.get("/live")
async def live() -> JSONResponse:
    return JSONResponse({"status": "ok", "ok": True})


@router.get("/ready")
async def ready() -> JSONResponse:
    # Short-circuit: if no startup delay is configured and we are not draining,
    # consider the app ready even if startup hooks haven't flipped the event yet.
    if not _draining and _read_ms("HEALTH_READY_DELAY_MS", 0) == 0:
        return JSONResponse({"status": "ok", "ok": True})

    if not _is_ready():
        return JSONResponse({"status": "starting", "ok": False}, status_code=503)
    return JSONResponse({"status": "ok", "ok": True})


# -------- Test helpers (no runtime effect) --------

def _enter_draining_for_tests() -> None:  # pragma: no cover
    global _draining
    _draining = True
    _ready_event.clear()


def _reset_readiness_for_tests() -> None:  # pragma: no cover
    global _draining
    _draining = False
    _ready_event.set()


async def _run_probe_once_for_tests() -> None:  # pragma: no cover
    await _run_probe_once()

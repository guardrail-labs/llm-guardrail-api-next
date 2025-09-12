# app/routes/version.py
# Summary (PR-R): Adds /version endpoint with build info + sanitized config snapshot.
# - /version: 200 with {"info": {...}, "config": {...}}
# - Info pulls from non-sensitive envs (APP_VERSION, GIT_SHA, BUILD_TIME) and lib versions.
# - Config snapshot uses the sanitizer (clamped/normalized) and a few safe toggles.
# - Router is auto-included by main.py's dynamic loader; no wiring changes.

from __future__ import annotations

import os
import platform
import sys
from typing import Any, Dict

import fastapi
import starlette
from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.services.config_sanitizer import (
    get_bool,
    get_int,
    get_verifier_latency_budget_ms,
    get_verifier_sampling_pct,
)

router = APIRouter()


def _info_payload() -> Dict[str, Any]:
    return {
        "version": os.getenv("APP_VERSION", "") or "",
        "commit": os.getenv("GIT_SHA", "") or "",
        "build_time": os.getenv("BUILD_TIME", "") or "",
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "fastapi": getattr(fastapi, "__version__", ""),
        "starlette": getattr(starlette, "__version__", ""),
    }


def _config_snapshot() -> Dict[str, Any]:
    # Only include normalized, non-sensitive toggles/knobs.
    return {
        "verifier_sampling_pct": get_verifier_sampling_pct(),
        "verifier_latency_budget_ms": get_verifier_latency_budget_ms(),
        "circuit_breaker_enabled": get_bool("VERIFIER_CB_ENABLED", default=False),
        "rate_limit_rps": get_int("RATE_LIMIT_RPS", default=60, min_value=0),
        "rate_limit_burst": get_int("RATE_LIMIT_BURST", default=60, min_value=0),
        "cors_enabled": get_bool("CORS_ENABLED", default=False),
        "api_security_enabled": get_bool("API_SECURITY_ENABLED", default=False),
    }


@router.get("/version")
async def version() -> JSONResponse:
    return JSONResponse({"info": _info_payload(), "config": _config_snapshot()})

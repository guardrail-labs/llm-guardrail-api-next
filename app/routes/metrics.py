# app/routes/metrics.py
# Summary (PR-X fix): Optional /metrics endpoint (Prometheus exposition).
# - Removes unused type: ignore comments; adds precise typing and narrowing.
# - Still disabled by default; enable via METRICS_ROUTE_ENABLED=1.
# - Optional API key via METRICS_API_KEY (X-API-KEY or Bearer).

from __future__ import annotations

import os
from typing import Any, Callable, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

router = APIRouter()

# Prometheus is optional; gracefully degrade to 404 if unavailable or disabled.
try:  # pragma: no cover
    from prometheus_client import REGISTRY as _REGISTRY  # type: ignore[assignment]
    from prometheus_client.exposition import (
        CONTENT_TYPE_LATEST as _CONTENT_TYPE_LATEST,  # type: ignore[assignment]
        generate_latest as _generate_latest,  # type: ignore[assignment]
    )

    REGISTRY: Any | None = _REGISTRY
    CONTENT_TYPE_LATEST: str = _CONTENT_TYPE_LATEST
    generate_latest: Optional[Callable[[Any], bytes]] = _generate_latest
except Exception:  # pragma: no cover
    REGISTRY = None
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"
    generate_latest = None


def _enabled() -> bool:
    return (os.getenv("METRICS_ROUTE_ENABLED", "") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _expected_key() -> Optional[str]:
    val = (os.getenv("METRICS_API_KEY", "") or "").strip()
    return val or None


def _auth_ok(request: Request, required: str) -> bool:
    # Accept either X-API-KEY: <key> or Authorization: Bearer <key>
    hdr_key = request.headers.get("x-api-key")
    if hdr_key and hdr_key == required:
        return True
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if token == required:
            return True
    return False


@router.get("/metrics")
async def metrics(request: Request) -> Response:
    if not _enabled() or generate_latest is None or REGISTRY is None:
        # Hidden unless explicitly enabled *and* prometheus_client is present.
        raise HTTPException(status_code=404, detail="Not Found")

    # Optional API key protection
    required = _expected_key()
    if required is not None and not _auth_ok(request, required):
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Narrow types for mypy
    assert generate_latest is not None
    assert REGISTRY is not None

    payload: bytes = generate_latest(REGISTRY)
    return Response(content=payload, media_type=CONTENT_TYPE_LATEST)

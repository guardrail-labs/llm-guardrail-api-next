# app/routes/metrics.py
# Summary: Prometheus /metrics exposition (enabled by default).
# - Enabled unless METRICS_ROUTE_ENABLED is an explicit "off" value.
# - Optional API key via METRICS_API_KEY (X-API-KEY or Bearer).

from __future__ import annotations

import os
from typing import Any, Callable, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

router = APIRouter()

# Prometheus is optional; degrade gracefully if unavailable.
try:  # pragma: no cover
    from prometheus_client import REGISTRY as PROM_REGISTRY
    from prometheus_client.exposition import (
        CONTENT_TYPE_LATEST as PROM_CONTENT_TYPE_LATEST,
        generate_latest as prom_generate_latest,
    )

    REGISTRY: Any | None = PROM_REGISTRY
    CONTENT_TYPE_LATEST: str = PROM_CONTENT_TYPE_LATEST
    generate_latest: Optional[Callable[[Any], bytes]] = prom_generate_latest
except Exception:  # pragma: no cover
    REGISTRY = None
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"
    generate_latest = None


_OFF_VALUES = {"0", "false", "no", "off"}


def _enabled() -> bool:
    raw = (os.getenv("METRICS_ROUTE_ENABLED", "") or "").strip().lower()
    # Default ON unless explicitly disabled.
    return raw == "" or raw not in _OFF_VALUES


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
        # Hidden unless enabled *and* prometheus_client is present.
        raise HTTPException(status_code=404, detail="Not Found")

    # Optional API key protection
    required = _expected_key()
    if required is not None and not _auth_ok(request, required):
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Ensure app-level metrics are imported so their collectors are registered.
    try:  # pragma: no cover
        import app.observability.metrics as _  # noqa: F401
    except Exception:
        # Do not fail exposition if metrics import has issues.
        pass

    # Narrow types for static analysis
    assert generate_latest is not None
    assert REGISTRY is not None

    payload: bytes = generate_latest(REGISTRY)
    return Response(content=payload, media_type=CONTENT_TYPE_LATEST)

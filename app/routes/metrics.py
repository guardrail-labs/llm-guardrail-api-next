# app/routes/metrics.py
# Summary (PR-X): Adds optional /metrics endpoint for Prometheus scrapes.
# - Disabled by default; enable with METRICS_ROUTE_ENABLED=1.
# - Optional protection via METRICS_API_KEY:
#     * Provide "X-API-KEY: <key>" or "Authorization: Bearer <key>".
# - Returns text/plain; version=0.0.4 (Prometheus exposition format).
# - Auto-included by main.py's dynamic route loader; no other wiring needed.

from __future__ import annotations

import os
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

router = APIRouter()

# Prometheus is optional; gracefully degrade to 404 if unavailable or disabled.
try:  # pragma: no cover
    from prometheus_client import REGISTRY  # type: ignore
    from prometheus_client.exposition import (  # type: ignore
        CONTENT_TYPE_LATEST,
        generate_latest,
    )
except Exception:  # pragma: no cover
    REGISTRY = None  # type: ignore[assignment]
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"  # fallback
    generate_latest = None  # type: ignore[assignment]


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
        # Let main.py handlers normalize this into JSON if needed elsewhere.
        raise HTTPException(status_code=401, detail="Unauthorized")

    payload: bytes = generate_latest(REGISTRY)  # type: ignore[call-arg]
    return Response(content=payload, media_type=CONTENT_TYPE_LATEST)


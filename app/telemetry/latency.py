# app/telemetry/latency.py
from __future__ import annotations

import time
from typing import Final

from fastapi import Request
from prometheus_client import Histogram
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from app.metrics.route_label import route_label

_LATENCY: Final[Histogram] = Histogram(
    "guardrail_latency_seconds",
    "Latency of HTTP requests handled by the Guardrail API.",
    labelnames=("route", "method"),
)


class LatencyHistogramMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        start = time.perf_counter()
        try:
            return await call_next(request)
        finally:
            dur = time.perf_counter() - start
            safe_route = route_label(request.url.path)
            _LATENCY.labels(route=safe_route, method=request.method).observe(dur)

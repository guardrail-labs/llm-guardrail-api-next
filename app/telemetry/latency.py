from __future__ import annotations

import time
from typing import Optional

from fastapi import Request
from prometheus_client import Histogram
from starlette.middleware.base import BaseHTTPMiddleware

# A simple histogram (no labels) suffices for tests
_LATENCY = Histogram(
    "guardrail_latency_seconds",
    "Latency of HTTP requests handled by the Guardrail API.",
)

class GuardrailLatencyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.perf_counter()
        try:
            return await call_next(request)
        finally:
            dur = time.perf_counter() - start
            _LATENCY.observe(dur)

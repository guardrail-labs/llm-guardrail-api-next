from __future__ import annotations

import os
import time
import threading
import uuid
from typing import Dict, List, Tuple

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.telemetry import metrics as tmetrics

# in-process rolling-window token buckets
_LOCK = threading.RLock()
_BUCKETS: Dict[str, List[float]] = {}
_LAST_CFG: Tuple[bool, int, int] = (False, 60, 60)
_LAST_APP_ID: int | None = None


def _cfg() -> Tuple[bool, int, int]:
    enabled = (os.environ.get("RATE_LIMIT_ENABLED") or "false").lower() == "true"
    per_min = int(os.environ.get("RATE_LIMIT_PER_MINUTE") or "60")
    burst = int(os.environ.get("RATE_LIMIT_BURST") or str(per_min))
    return enabled, per_min, burst


def _key(request: Request) -> str:
    host = request.client.host if request.client else "unknown"
    tenant = request.headers.get("X-Tenant-ID") or "default"
    bot = request.headers.get("X-Bot-ID") or "default"
    return f"{host}:{tenant}:{bot}"


def _allow_and_remaining(request: Request) -> Tuple[bool, int]:
    global _LAST_CFG, _LAST_APP_ID
    app_id = id(request.app)
    if _LAST_APP_ID != app_id:
        with _LOCK:
            _BUCKETS.clear()
            _LAST_APP_ID = app_id

    enabled, per_min, burst = _cfg()
    if (enabled, per_min, burst) != _LAST_CFG:
        with _LOCK:
            _BUCKETS.clear()
            _LAST_CFG = (enabled, per_min, burst)

    if not enabled:
        # not limited; remaining is burst
        return True, burst

    now = time.time()
    cutoff = now - 60.0
    k = _key(request)
    with _LOCK:
        win = _BUCKETS.setdefault(k, [])
        # prune old
        win[:] = [t for t in win if t >= cutoff]
        if len(win) >= burst:
            return False, 0
        win.append(now)
        remaining = max(burst - len(win), 0)
        return True, remaining


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        enabled, per_min, burst = _cfg()
        allowed, remaining = _allow_and_remaining(request)

        # Always expose limit headers (even if disabled)
        limit_val = str(per_min)
        remaining_val = str(remaining)

        if not allowed:
            # try to tick metric, but don't break on failure
            try:
                tmetrics.inc_rate_limited(1.0)
            except Exception:
                import logging
                logging.warning("inc_rate_limited failed")

            rid = getattr(request.state, "request_id", "") or str(uuid.uuid4())
            retry_after = 60
            body = {
                "code": "rate_limited",
                "detail": "rate limit exceeded",  # lowercase (tests expect this)
                "retry_after": int(retry_after),
                "request_id": rid,
            }
            return JSONResponse(
                status_code=429,
                content=body,
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": limit_val,
                    "X-RateLimit-Remaining": remaining_val,
                    "X-Request-ID": rid,
                },
            )

        resp = await call_next(request)
        # attach headers on successful responses too
        resp.headers.setdefault("X-RateLimit-Limit", limit_val)
        resp.headers.setdefault("X-RateLimit-Remaining", remaining_val)
        return resp

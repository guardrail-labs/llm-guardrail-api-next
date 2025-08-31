from __future__ import annotations

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.services.rate_limit import RateLimiter
from app.telemetry.metrics import inc_rate_limited  # <-- NEW

TENANT_HEADER = "X-Tenant-ID"
BOT_HEADER = "X-Bot-ID"

class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Tenant/Bot-aware rate limiting.
    - Uses app.state configured in app/main.py (_init_rate_limit_state).
    - Always emits headers:
        X-RateLimit-Limit
        X-RateLimit-Remaining
        X-RateLimit-Reset
    - Returns 429 when enabled AND bucket empty.
    """
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.limiter = RateLimiter()  # in-memory; swap to Redis in prod

    async def dispatch(self, request: Request, call_next):
        st = request.app.state

        enabled = bool(getattr(st, "rate_limit_enabled", False))
        per_minute = int(getattr(st, "rate_limit_per_minute", 60))
        burst = int(getattr(st, "rate_limit_burst", per_minute))

        tenant_id = request.headers.get(TENANT_HEADER, "")
        bot_id = request.headers.get(BOT_HEADER, "")

        allowed, remaining, limit, reset_epoch = self.limiter.check_and_consume(
            enabled=enabled,
            tenant_id=tenant_id,
            bot_id=bot_id,
            per_minute=per_minute,
            burst=burst,
        )

        if not allowed:
            # increment metric for rate-limited requests
            inc_rate_limited(1.0)
            resp = Response(
                content='{"detail":"rate limit exceeded"}',
                media_type="application/json",
                status_code=429,
            )
            resp.headers["X-RateLimit-Limit"] = str(limit)
            resp.headers["X-RateLimit-Remaining"] = "0"
            resp.headers["X-RateLimit-Reset"] = str(reset_epoch)
            # Retry-After (seconds until at least 1 token refills)
            import time as _t
            retry_after = max(0, int(reset_epoch - int(_t.time())))
            resp.headers["Retry-After"] = str(retry_after)
            return resp

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, remaining))
        response.headers["X-RateLimit-Reset"] = str(reset_epoch)
        return response

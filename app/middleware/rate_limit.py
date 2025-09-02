from __future__ import annotations

import logging
import uuid

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

from app.services.rate_limit import RateLimiter
from app.shared.headers import BOT_HEADER, TENANT_HEADER
from app.telemetry.metrics import inc_rate_limited

logger = logging.getLogger(__name__)


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
            # Increment metric for rate-limited requests; ignore failures
            try:
                inc_rate_limited()
            except Exception:
                logger.warning("inc_rate_limited failed", exc_info=True)

            rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
            body = {
                "code": "rate_limited",
                "detail": "rate limit exceeded",
                "retry_after": 60,
                "request_id": rid,
            }
            resp = JSONResponse(status_code=429, content=body)
            # Required by tests
            resp.headers["Retry-After"] = "60"
            resp.headers["X-RateLimit-Limit"] = str(limit)
            resp.headers["X-RateLimit-Remaining"] = "0"
            resp.headers["X-RateLimit-Reset"] = str(reset_epoch)
            # Make 429 self-sufficient even if we're the outermost middleware:
            resp.headers["X-Request-ID"] = rid
            # Optional hardening headers for consistency
            resp.headers["X-Content-Type-Options"] = "nosniff"
            resp.headers["X-Frame-Options"] = "DENY"
            resp.headers["X-XSS-Protection"] = "0"
            resp.headers["Referrer-Policy"] = "no-referrer"
            return resp

        response: Response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, remaining))
        response.headers["X-RateLimit-Reset"] = str(reset_epoch)
        return response

# app/middleware/rate_limit.py
from __future__ import annotations

import logging
import time
from typing import Dict, Tuple

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from app.config import get_settings
from app.telemetry.metrics import inc_rate_limited  # tests patch this

# Logger for warnings (caplog looks for the phrase)
logger = logging.getLogger("app.ratelimit")

# In-process token buckets keyed by (tenant, bot)
_buckets: Dict[Tuple[str, str], Dict[str, float]] = {}


def _key(tenant: str, bot: str) -> Tuple[str, str]:
    return (tenant or "default", bot or "default")


class RateLimitMiddleware:
    """
    Token-bucket limiter that:
      - Enforces when RATE_LIMIT_ENABLED=true
      - Always sets X-RateLimit-* headers (even when disabled)
      - Emits inc_rate_limited() and logs "inc_rate_limited failed" on exception
      - Produces 429 body with exact contract and lower-case detail
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        s = get_settings()
        headers = dict(scope.get("headers", []))
        tenant = headers.get(b"x-tenant-id", b"").decode() or "default"
        bot = headers.get(b"x-bot-id", b"").decode() or "default"

        rps = max(1, int(s.RATE_LIMIT_PER_MINUTE)) / 60.0
        burst = max(1, int(s.RATE_LIMIT_BURST))
        now = time.time()

        k = _key(tenant, bot)
        bucket = _buckets.get(k)
        if bucket is None:
            bucket = {"tokens": float(burst), "ts": now}
            _buckets[k] = bucket

        # Refill tokens
        elapsed = max(0.0, now - float(bucket["ts"]))
        bucket["ts"] = now
        tokens = float(bucket["tokens"]) + elapsed * rps
        if tokens > burst:
            tokens = float(burst)

        enforce = bool(s.RATE_LIMIT_ENABLED)
        allowed = True
        if enforce:
            if tokens >= 1.0:
                tokens -= 1.0
            else:
                allowed = False

        # Persist tokens
        bucket["tokens"] = tokens

        # Prepare standard rate-limit headers
        # Reset approximates next token availability
        reset_epoch = int(now + max(0.0, (1.0 - tokens) / rps)) if rps > 0 else int(now)
        limit_hdr = str(int(s.RATE_LIMIT_PER_MINUTE))
        remaining_hdr = str(max(0, int(tokens * 60.0)))

        def _set_headers(message):
            hdrs = message.setdefault("headers", [])

            def set_header(k: str, v: str) -> None:
                hdrs.append((k.encode("latin-1"), v.encode("latin-1")))

            set_header("X-RateLimit-Limit", limit_hdr)
            set_header("X-RateLimit-Remaining", remaining_hdr)
            set_header("X-RateLimit-Reset", str(reset_epoch))

        if not allowed:
            # Metric + warning on failure (exact phrase asserted in tests)
            try:
                inc_rate_limited(1.0)
            except Exception as e:  # pragma: no cover
                logger.warning("inc_rate_limited failed", exc_info=e)

            body = {
                "code": "rate_limited",
                "detail": "rate limit exceeded",
                "retry_after": 60,
            }

            async def _send_429(message):
                if message.get("type") == "http.response.start":
                    _set_headers(message)
                    headers_list = message.setdefault("headers", [])
                    headers_list.append((b"Retry-After", b"60"))
                await send(message)

            response = JSONResponse(status_code=429, content=body)
            await response(scope, receive, _send_429)
            return

        # Allowed: forward but still add headers
        async def send_wrapped(message):
            if message.get("type") == "http.response.start":
                _set_headers(message)
            await send(message)

        await self.app(scope, receive, send_wrapped)

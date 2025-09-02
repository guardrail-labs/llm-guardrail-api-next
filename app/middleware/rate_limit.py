# app/middleware/rate_limit.py
from __future__ import annotations
import time
from typing import Dict, Tuple
from starlette.types import ASGIApp, Scope, Receive, Send
from starlette.responses import JSONResponse

from app.config import get_settings
from app.telemetry.metrics import inc_rate_limited  # tests patch this
from app.telemetry.logging import log_event

# Simple in-process token buckets keyed by (tenant, bot) + path/method pair
# Good enough for unit tests; production can swap to Redis via services layer.
_buckets: Dict[Tuple[str, str], Dict[str, float]] = {}  # tokens + last_refill_ts

def _key(tenant: str, bot: str) -> Tuple[str, str]:
    return (tenant or "default", bot or "default")

class RateLimitMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        s = get_settings()
        # Read identifying headers (tests use these names)
        headers = dict(scope.get("headers", []))
        tenant = headers.get(b"x-tenant-id", b"").decode() or "default"
        bot = headers.get(b"x-bot-id", b"").decode() or "default"

        # Per-minute to per-second
        rps = max(1, int(s.RATE_LIMIT_PER_MINUTE)) / 60.0
        burst = max(1, int(s.RATE_LIMIT_BURST))
        now = time.time()

        k = _key(tenant, bot)
        bucket = _buckets.get(k)
        if bucket is None:
            bucket = {"tokens": float(burst), "ts": now}
            _buckets[k] = bucket

        # Refill
        elapsed = max(0.0, now - float(bucket["ts"]))
        bucket["ts"] = now
        tokens = float(bucket["tokens"]) + elapsed * rps
        if tokens > burst:
            tokens = float(burst)

        # Decide
        enforce = bool(s.RATE_LIMIT_ENABLED)
        allowed = True
        if enforce:
            if tokens >= 1.0:
                tokens -= 1.0
            else:
                allowed = False

        # Persist tokens
        bucket["tokens"] = tokens

        # Common headers (must be present even when disabled)
        # X-RateLimit-Reset ~= next whole second token replenishes (epoch seconds)
        reset_epoch = int(now + max(0.0, (1.0 - tokens) / rps)) if rps > 0 else int(now)
        limit_hdr = str(int(s.RATE_LIMIT_PER_MINUTE))
        # Remaining is approximate (per-minute view). Provide a simple floor at 0.
        remaining_hdr = str(max(0, int(tokens * 60.0)))

        def _set_headers(message):
            headers_list = message.setdefault("headers", [])
            def set_header(k: str, v: str) -> None:
                headers_list.append((k.encode("latin-1"), v.encode("latin-1")))
            set_header("X-RateLimit-Limit", limit_hdr)
            set_header("X-RateLimit-Remaining", remaining_hdr)
            set_header("X-RateLimit-Reset", str(reset_epoch))

        if not allowed:
            # Emit metric; warn on failure per tests
            try:
                inc_rate_limited(1.0)
            except Exception as e:  # pragma: no cover
                log_event("warn", msg="inc_rate_limited failed", error=str(e))

            # Build 429 response with exact contract/casing
            # detail must be lower-case per tests
            # Include Retry-After and X-RateLimit-* and X-Request-ID (added by RequestID middleware)
            body = {
                "code": "rate_limited",
                "detail": "rate limit exceeded",
                "retry_after": 60,
            }
            # Wrap send to inject headers
            async def _send_429(message):
                if message.get("type") == "http.response.start":
                    _set_headers(message)
                    headers_list = message.setdefault("headers", [])
                    headers_list.append((b"Retry-After", b"60"))
                await send(message)

            response = JSONResponse(status_code=429, content=body)
            await response(scope, receive, _send_429)
            return

        # Allowed path: proxy through, but still add headers
        async def send_wrapped(message):
            if message.get("type") == "http.response.start":
                _set_headers(message)
            await send(message)

        await self.app(scope, receive, send_wrapped)

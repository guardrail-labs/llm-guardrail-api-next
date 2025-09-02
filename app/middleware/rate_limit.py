from __future__ import annotations

import logging
import time
import uuid
from typing import Dict, Tuple

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from app.config import get_settings
from app.telemetry.metrics import inc_rate_limited  # tests patch this
from app.telemetry.tracing import get_trace_id as _get_trace_id

logger = logging.getLogger("app.ratelimit")


def _tenant_bot_from_scope(scope: Scope) -> Tuple[str, str]:
    headers = dict(scope.get("headers", []))
    tenant = headers.get(b"x-tenant-id", b"").decode() or "default"
    bot = headers.get(b"x-bot-id", b"").decode() or "default"
    return tenant, bot


class RateLimitMiddleware:
    """
    Token-bucket limiter that:
      - Enforces when RATE_LIMIT_ENABLED=true
      - Always sets X-RateLimit-* headers (even when disabled)
      - Emits inc_rate_limited() and logs "inc_rate_limited failed" on exception
      - Produces 429 body with exact contract and includes request_id
      - Keeps buckets per-app-instance (no cross-test leakage)
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        # Per-instance buckets: {(tenant, bot): {"tokens": float, "ts": float}}
        self._buckets: Dict[Tuple[str, str], Dict[str, float]] = {}

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        s = get_settings()
        tenant, bot = _tenant_bot_from_scope(scope)

        # per-minute -> per-second
        rps = max(1, int(s.RATE_LIMIT_PER_MINUTE)) / 60.0
        burst = max(1, int(s.RATE_LIMIT_BURST))
        now = time.time()

        k = (tenant, bot)
        bucket = self._buckets.get(k)
        if bucket is None:
            bucket = {"tokens": float(burst), "ts": now}
            self._buckets[k] = bucket

        # Refill
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
        reset_epoch = int(now + max(0.0, (1.0 - tokens) / rps)) if rps > 0 else int(now)
        limit_hdr = str(int(s.RATE_LIMIT_PER_MINUTE))
        remaining_hdr = str(max(0, int(tokens * 60.0)))

        def _set_rl_headers(message):
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

            # Ensure X-Request-ID is present in headers AND body
            incoming = dict(scope.get("headers", []))
            rid = incoming.get(b"x-request-id")
            request_id = rid.decode() if rid else str(uuid.uuid4())

            trace_id = _get_trace_id()

            body = {
                "code": "rate_limited",
                "detail": "rate limit exceeded",
                "retry_after": 60,
                "request_id": request_id,
            }
            if trace_id:
                body["trace_id"] = trace_id

            async def _send_429(message):
                if message.get("type") == "http.response.start":
                    _set_rl_headers(message)
                    headers_list = message.setdefault("headers", [])
                    headers_list.append((b"Retry-After", b"60"))
                    headers_list.append((b"X-Request-ID", request_id.encode("latin-1")))
                    if trace_id:
                        headers_list.append((b"X-Trace-ID", trace_id.encode("latin-1")))
                await send(message)

            response = JSONResponse(status_code=429, content=body)
            await response(scope, receive, _send_429)
            return

        # Allowed: forward but still add RL headers
        async def send_wrapped(message):
            if message.get("type") == "http.response.start":
                _set_rl_headers(message)
            await send(message)

        await self.app(scope, receive, send_wrapped)

"""Simple token-bucket rate limiter (in-memory)."""
from __future__ import annotations

import time
from typing import Tuple

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.config import Settings
from app.telemetry.metrics import inc_rate_limited


def _now() -> float:
    return time.monotonic()


def _extract_presented_key(request: Request) -> Tuple[str, str]:
    """
    Return (key_type, key_value):
      - ("api_key", <X-API-Key or Bearer token>)
      - ("ip", <client ip>) if no key header present (auth will still reject later)
    """
    x_api_key = request.headers.get("X-API-Key")
    if x_api_key:
        return "api_key", x_api_key

    auth = request.headers.get("Authorization")
    if auth and auth.lower().startswith("bearer "):
        return "api_key", auth[7:].strip()

    client_ip = request.client.host if request.client else "unknown"
    return "ip", client_ip


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app) -> None:  # type: ignore[override]
        super().__init__(app)
        s = Settings()  # read env at app-build time

        # Config (Pydantic converts "true"/"1"/etc. to bool for us)
        self.enabled: bool = bool(s.RATE_LIMIT_ENABLED)
        self.per_minute: int = int(s.RATE_LIMIT_PER_MINUTE)
        self.burst: int = int(s.RATE_LIMIT_BURST or self.per_minute)
        self.tokens_per_sec: float = self.per_minute / 60.0

        # Buckets: key -> (tokens, last_refill_ts)
        self._buckets: dict[str, tuple[float, float]] = {}

    async def dispatch(self, request: Request, call_next):
        # Only limit the guardrail endpoint (and only when enabled)
        if not self.enabled or request.url.path != "/guardrail":
            return await call_next(request)

        _, key_value = _extract_presented_key(request)
        now = _now()

        tokens, last = self._buckets.get(key_value, (float(self.burst), now))

        # Refill tokens based on elapsed time
        elapsed = max(0.0, now - last)
        tokens = min(self.burst, tokens + elapsed * self.tokens_per_sec)

        if tokens < 1.0:
            # Out of tokens: record metric and reject
            try:
                inc_rate_limited()
            except Exception:
                pass
            return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})

        # Consume one token and proceed
        tokens -= 1.0
        self._buckets[key_value] = (tokens, now)
        return await call_next(request)

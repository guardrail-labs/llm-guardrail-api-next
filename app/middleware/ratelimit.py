from __future__ import annotations

import asyncio
import time
from typing import Optional

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.config import get_settings
from app.telemetry.metrics import inc_rate_limited

try:
    # redis-py 5.x asyncio client (optional)
    from redis import asyncio as aioredis  # type: ignore[import-not-found]
except Exception:  # noqa: BLE001
    aioredis = None  # type: ignore[assignment]


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Token-bucket rate limiting with optional Redis backend.

    Keys by API key (preferred) or client IP. Defaults to disabled.
    """

    def __init__(self, app) -> None:  # type: ignore[override]
        super().__init__(app)
        s = get_settings()
        self.enabled: bool = bool(str(s.__dict__.get("RATE_LIMIT_ENABLED", False)).lower() in ("1", "true", "yes"))
        self.per_minute: int = int(getattr(s, "RATE_LIMIT_PER_MINUTE", 60))
        self.burst: int = int(getattr(s, "RATE_LIMIT_BURST", self.per_minute))
        self.backend: str = getattr(s, "RATE_LIMIT_BACKEND", "memory")
        self.redis_url: Optional[str] = getattr(s, "REDIS_URL", None)

        # Memory store: key -> (tokens, last_ts)
        self._mem: dict[str, tuple[float, float]] = {}

        # Redis
        self._redis = None
        if self.enabled and self.backend == "redis" and self.redis_url and aioredis:
            self._redis = aioredis.from_url(self.redis_url, encoding="utf-8", decode_responses=True)

        # Refill rate tokens per second
        self._refill = self.per_minute / 60.0

        # Mutex for in-memory updates
        self._lock = asyncio.Lock()

    async def dispatch(self, request: Request, call_next):
        if not self.enabled:
            return await call_next(request)

        key = self._rate_key(request)
        allowed = await self._consume_token(key)

        if not allowed:
            inc_rate_limited()
            return JSONResponse({"detail": "Too Many Requests"}, status_code=429)

        return await call_next(request)

    def _rate_key(self, request: Request) -> str:
        # Prefer API key scoping; fallback to remote IP
        api_key = request.headers.get("X-API-Key")
        if not api_key:
            auth = request.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                api_key = auth.split(" ", 1)[1].strip()
        if api_key:
            return f"ratelimit:api:{api_key}"
        ip = request.client.host if request.client else "unknown"
        return f"ratelimit:ip:{ip}"

    async def _consume_token(self, key: str) -> bool:
        now = time.time()
        if self._redis:
            return await self._consume_token_redis(key, now)
        return await self._consume_token_memory(key, now)

    async def _consume_token_memory(self, key: str, now: float) -> bool:
        async with self._lock:
            tokens, last_ts = self._mem.get(key, (float(self.burst), now))
            # Refill tokens
            tokens = min(self.burst, tokens + (now - last_ts) * self._refill)
            if tokens >= 1.0:
                tokens -= 1.0
                self._mem[key] = (tokens, now)
                return True
            else:
                self._mem[key] = (tokens, now)
                return False

    async def _consume_token_redis(self, key: str, now: float) -> bool:
        # Stored as two fields in a hash: tokens, ts
        # Use a simple LUA-less algorithm with WATCH/MULTI to keep it readable;
        # here we keep it best-effort without strict atomicity guarantees.
        assert self._redis is not None
        pipe = self._redis.pipeline()
        try:
            # Get current
            pipe.hget(key, "tokens")
            pipe.hget(key, "ts")
            tokens_s, ts_s = await pipe.execute()
            tokens = float(tokens_s) if tokens_s is not None else float(self.burst)
            last_ts = float(ts_s) if ts_s is not None else now
            # Refill
            tokens = min(self.burst, tokens + (now - last_ts) * self._refill)
            if tokens >= 1.0:
                tokens -= 1.0
                pipe.hset(key, mapping={"tokens": tokens, "ts": now})
                # TTL 2 minutes to auto-expire idle buckets
                pipe.expire(key, 120)
                await pipe.execute()
                return True
            else:
                pipe.hset(key, mapping={"tokens": tokens, "ts": now})
                pipe.expire(key, 120)
                await pipe.execute()
                return False
        finally:
            try:
                await pipe.close()
            except Exception:  # noqa: BLE001
                pass


from __future__ import annotations

import asyncio
import importlib
import time
from typing import TYPE_CHECKING, Any, Optional, cast

from fastapi import Request
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import get_settings
from app.telemetry.metrics import inc_rate_limited

if TYPE_CHECKING:  # pragma: no cover
    from redis.asyncio import Redis as RedisClient
else:
    RedisClient = Any


def _truthy(val: object) -> bool:
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Token-bucket rate limiting with optional Redis backend.
    Keys by API key (preferred) or client IP.
    """

    def __init__(self, app) -> None:
        super().__init__(app)
        s = get_settings()

        self.enabled: bool = _truthy(getattr(s, "RATE_LIMIT_ENABLED", False))
        self.per_minute: int = int(getattr(s, "RATE_LIMIT_PER_MINUTE", 60))
        self.burst: int = int(getattr(s, "RATE_LIMIT_BURST", self.per_minute))
        self.backend: str = getattr(s, "RATE_LIMIT_BACKEND", "memory")
        self.redis_url: Optional[str] = getattr(s, "REDIS_URL", None)

        self._mem: dict[str, tuple[float, float]] = {}
        self._redis: Optional[RedisClient] = None
        if self.enabled and self.backend == "redis" and self.redis_url:
            mod = self._try_import_redis_asyncio()
            if mod is not None:
                self._redis = cast(
                    RedisClient,
                    mod.from_url(self.redis_url, encoding="utf-8", decode_responses=True),
                )

        self._refill = self.per_minute / 60.0
        self._lock = asyncio.Lock()

    @staticmethod
    def _try_import_redis_asyncio() -> Any | None:
        try:  # pragma: no cover
            return importlib.import_module("redis.asyncio")
        except Exception:
            return None

    async def dispatch(self, request: Request, call_next):
        if not self.enabled:
            return await call_next(request)

        path = request.url.path
        # Do not rate-limit clearly public endpoints
        if path in {"/health", "/metrics"}:
            return await call_next(request)

        key = self._rate_key(request)
        allowed = await self._consume_token(key)
        if not allowed:
            inc_rate_limited()
            # Let global error handler format JSON and X-Request-ID.
            # Provide Retry-After to satisfy tests and clients.
            raise StarletteHTTPException(
                status_code=429,
                detail="rate_limited",
                headers={"Retry-After": "30"},
            )

        return await call_next(request)

    def _rate_key(self, request: Request) -> str:
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
            tokens = min(self.burst, tokens + (now - last_ts) * self._refill)
            if tokens >= 1.0:
                tokens -= 1.0
                self._mem[key] = (tokens, now)
                return True
            self._mem[key] = (tokens, now)
            return False

    async def _consume_token_redis(self, key: str, now: float) -> bool:
        assert self._redis is not None
        pipe = self._redis.pipeline()
        try:
            pipe.hget(key, "tokens")
            pipe.hget(key, "ts")
            tokens_s, ts_s = await pipe.execute()
            tokens = float(tokens_s) if tokens_s is not None else float(self.burst)
            last_ts = float(ts_s) if ts_s is not None else now

            tokens = min(self.burst, tokens + (now - last_ts) * self._refill)
            if tokens >= 1.0:
                tokens -= 1.0
                pipe.hset(key, mapping={"tokens": tokens, "ts": now})
                pipe.expire(key, 120)
                await pipe.execute()
                return True

            pipe.hset(key, mapping={"tokens": tokens, "ts": now})
            pipe.expire(key, 120)
            await pipe.execute()
            return False
        finally:
            try:
                await pipe.close()
            except Exception:
                pass

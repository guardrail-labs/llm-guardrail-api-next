from __future__ import annotations

import os
import time
import uuid
from typing import Awaitable, Callable, Dict, Optional, Tuple, cast

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from app import settings
from app.middleware.request_id import get_request_id

# Header and context keys
_API_KEY_HDR = "X-API-Key"


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    text = str(raw).strip()
    if not text:
        return default
    try:
        return int(float(text))
    except (TypeError, ValueError):
        return default


def _bool_env(v: object, default: bool) -> bool:
    if v is None:
        return default
    s = str(v).strip().lower()
    return s in {"1", "true", "t", "yes", "y", "on"}


class _MemoryBucket:
    """
    Simple per-process token bucket.
    capacity: maximum tokens (burst)
    rate: tokens per second (per_min / 60)
    """

    __slots__ = ("tokens", "capacity", "rate", "last_ts")

    def __init__(self, capacity: int, rate: float) -> None:
        self.capacity = max(1, capacity)
        self.rate = max(0.0, rate)
        self.tokens = float(self.capacity)
        self.last_ts = time.monotonic()

    def allow(self, cost: float = 1.0) -> Tuple[bool, float]:
        now = time.monotonic()
        delta = now - self.last_ts
        if delta > 0.0 and self.rate > 0.0:
            self.tokens = min(self.capacity, self.tokens + delta * self.rate)
        self.last_ts = now

        if self.tokens >= cost:
            self.tokens -= cost
            return True, 0.0

        # Compute retry-after seconds to next available token
        shortfall = cost - self.tokens
        wait_s = 0.0 if self.rate <= 0.0 else shortfall / self.rate
        return False, max(0.0, wait_s)


class _MemoryLimiter:
    """
    In-memory limiter keyed by API key (or client IP if header absent).
    """

    def __init__(self, per_min: int, burst: int) -> None:
        rate = float(per_min) / 60.0
        self._buckets: Dict[str, _MemoryBucket] = {}
        self._capacity = max(1, int(burst))
        self._rate = rate

    def _bucket_for(self, key: str) -> _MemoryBucket:
        b = self._buckets.get(key)
        if b is None:
            b = _MemoryBucket(capacity=self._capacity, rate=self._rate)
            self._buckets[key] = b
        return b

    def allow(self, key: str) -> Tuple[bool, float]:
        return self._bucket_for(key).allow(1.0)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware that supports "memory" or "redis" backends.
    This hotfix ensures the memory backend enforces regardless of REDIS_URL.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

        enabled_source: object = os.getenv("RATE_LIMIT_ENABLED")
        if enabled_source is None:
            enabled_source = getattr(settings, "RATE_LIMIT_ENABLED", False)
        enabled = _bool_env(enabled_source, False)
        self.enabled: bool = bool(enabled)

        backend_source = os.getenv("RATE_LIMIT_BACKEND")
        if backend_source is None:
            backend_source = getattr(settings, "RATE_LIMIT_BACKEND", "memory")
        backend = str(backend_source or "memory").strip().lower() or "memory"
        if backend not in {"memory", "redis"}:
            backend = "memory"
        self.backend = backend

        # Memory backend configuration
        default_per_min = int(getattr(settings, "RATE_LIMIT_PER_MINUTE", 60) or 60)
        per_min = _int_env("RATE_LIMIT_PER_MINUTE", default_per_min)
        default_burst = int(getattr(settings, "RATE_LIMIT_BURST", per_min) or per_min)
        burst = _int_env("RATE_LIMIT_BURST", default_burst)
        self._limit_per_minute = per_min
        self._burst = burst
        self._mem: Optional[_MemoryLimiter] = None
        if self.enabled and self.backend == "memory":
            self._mem = _MemoryLimiter(per_min=per_min, burst=burst)

        # Unknown principals enforcement
        enforce_source: object = os.getenv("RATE_LIMIT_ENFORCE_UNKNOWN")
        if enforce_source is None:
            enforce_source = getattr(settings, "RATE_LIMIT_ENFORCE_UNKNOWN", True)
        self.enforce_unknown = _bool_env(enforce_source, True)

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if not self.enabled:
            return await call_next(request)

        # Identify principal
        api_key = request.headers.get(_API_KEY_HDR, "").strip()
        principal = api_key or (request.client.host if request.client else "unknown")

        if not api_key and not self.enforce_unknown:
            return await call_next(request)

        allowed, retry_after = await self._allow(principal)
        if allowed:
            return await call_next(request)

        retry_seconds = max(1, int(retry_after or 1))
        request_id = (
            request.headers.get("X-Request-ID")
            or get_request_id()
            or str(uuid.uuid4())
        )
        payload = {
            "detail": "Rate limit exceeded",
            "retry_after_seconds": retry_seconds,
        }
        if request_id:
            payload["request_id"] = request_id

        try:
            request.state.guardrail_decision = {
                "outcome": "block_input_only",
                "mode": "Tier1",
                "incident_id": f"rl-{principal}",
            }
        except Exception:
            pass

        headers = {
            "Retry-After": str(retry_seconds),
            "X-RateLimit-Limit": f"{self._limit_per_minute}; burst={self._burst}",
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Policy": f"{self.backend}",
        }
        if request_id:
            headers.setdefault("X-Request-ID", request_id)

        return JSONResponse(status_code=429, content=payload, headers=headers)

    async def _allow(self, principal: str) -> Tuple[bool, float]:
        if self.backend == "memory":
            assert self._mem is not None  # mypy: set when enabled
            return self._mem.allow(principal)
        # Redis path (existing behavior preserved)
        return await self._allow_redis(principal)

    async def _allow_redis(self, principal: str) -> Tuple[bool, float]:
        """
        Defer to existing Redis gate if present. If Redis is unavailable or
        misconfigured, fallback to a conservative "allow=False" with small
        retry to avoid silent bypasses. This keeps parity with tests that
        explicitly select the memory backend.
        """

        try:
            from app.rate_limit.redis_gate import allow as redis_allow
        except Exception:
            # Redis gate not available; safest is to throttle with short retry
            return False, 1.0
        redis_func: Callable[[str], Awaitable[Tuple[bool, float]]]
        redis_func = cast(
            Callable[[str], Awaitable[Tuple[bool, float]]],
            redis_allow,
        )
        return await redis_func(principal)

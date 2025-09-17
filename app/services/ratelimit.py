from __future__ import annotations

import math
import os
import threading
from time import monotonic as _monotonic
from typing import Dict, Optional, Tuple

from prometheus_client import REGISTRY, Counter, Gauge


def _get_or_create_metric(factory, name: str, documentation: str, **kwargs):
    try:
        return factory(name, documentation, **kwargs)
    except ValueError:
        existing = getattr(REGISTRY, "_names_to_collectors", {}).get(name)
        if existing is not None:
            return existing
        raise


RATE_LIMIT_BLOCKS = _get_or_create_metric(
    Counter,
    "guardrail_rate_limited_total",
    "Total number of requests blocked by rate limiting",
    labelnames=("tenant", "bot"),
)

TOKENS_GAUGE = _get_or_create_metric(
    Gauge,
    "guardrail_ratelimit_tokens",
    "Current tokens available in the bucket",
    labelnames=("tenant", "bot"),
)


def _now() -> float:
    return _monotonic()


class TokenBucket:
    __slots__ = ("capacity", "refill_rate", "tokens", "last", "lock")

    def __init__(self, capacity: float, refill_rate: float) -> None:
        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate)
        self.tokens = float(capacity)
        self.last = _now()
        self.lock = threading.Lock()

    def _refill(self, t: float) -> None:
        if t <= self.last:
            return
        delta = t - self.last
        self.tokens = min(self.capacity, self.tokens + delta * self.refill_rate)
        self.last = t

    def allow(self, cost: float = 1.0) -> Tuple[bool, Optional[int], float]:
        with self.lock:
            t = _now()
            self._refill(t)
            if self.tokens >= cost:
                self.tokens -= cost
                return True, None, self.tokens
            need = max(0.0, cost - self.tokens)
            if self.refill_rate <= 0:
                return False, 1, self.tokens
            wait = need / self.refill_rate
            retry_after = max(1, int(math.ceil(wait)))
            return False, retry_after, self.tokens


class RateLimiter:
    def __init__(self, capacity: float, refill_rate: float) -> None:
        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate)
        self._buckets: Dict[Tuple[str, str], TokenBucket] = {}
        self._lock = threading.Lock()

    def _bucket_for(self, tenant: str, bot: str) -> TokenBucket:
        key = (tenant, bot)
        bucket = self._buckets.get(key)
        if bucket is not None:
            return bucket
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = TokenBucket(self.capacity, self.refill_rate)
                self._buckets[key] = bucket
            return bucket

    def allow(self, tenant: str, bot: str, cost: float = 1.0) -> Tuple[bool, Optional[int], float]:
        bucket = self._bucket_for(tenant, bot)
        ok, retry_after, remaining = bucket.allow(cost)
        try:
            TOKENS_GAUGE.labels(tenant=tenant, bot=bot).set(max(0.0, remaining))
        except Exception:
            pass
        return ok, retry_after, remaining


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _float_env(name: str, default: float) -> float:
    value = os.getenv(name)
    try:
        return float(value) if value is not None else default
    except Exception:
        return default


def build_from_settings(settings) -> Tuple[bool, RateLimiter]:
    enabled = True
    rps = 5.0
    burst = 10.0
    try:
        ingress = getattr(getattr(settings, "ingress"), "rate_limit", None)
        if ingress is not None:
            enabled = bool(getattr(ingress, "enabled", enabled))
            rps = float(getattr(ingress, "rps", rps))
            burst = float(getattr(ingress, "burst", burst))
        else:
            enabled = _bool_env("RATE_LIMIT_ENABLED", True)
            rps = _float_env("RATE_LIMIT_RPS", 5.0)
            burst = _float_env("RATE_LIMIT_BURST", 10.0)
    except Exception:
        enabled = _bool_env("RATE_LIMIT_ENABLED", True)
        rps = _float_env("RATE_LIMIT_RPS", 5.0)
        burst = _float_env("RATE_LIMIT_BURST", 10.0)
    return enabled, RateLimiter(capacity=burst, refill_rate=rps)


_global_enabled: Optional[bool] = None
_global_limiter: Optional[RateLimiter] = None


def get_global(settings=None) -> Tuple[bool, RateLimiter]:
    global _global_enabled, _global_limiter
    if _global_limiter is not None and _global_enabled is not None:
        return _global_enabled, _global_limiter
    enabled, limiter = build_from_settings(getattr(settings, "value", settings))
    _global_enabled, _global_limiter = enabled, limiter
    return enabled, limiter

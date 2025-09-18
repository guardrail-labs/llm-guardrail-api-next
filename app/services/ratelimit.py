from __future__ import annotations

import math
import os
from time import monotonic as _monotonic
from typing import Optional, Tuple

from prometheus_client import REGISTRY, Counter, Gauge

try:  # pragma: no cover - defensive import, exercised in tests
    from app.services.ratelimit_backends import (
        LocalTokenBucket,
        RateLimiterBackend,
        build_backend,
    )
except Exception:  # pragma: no cover
    LocalTokenBucket = None  # type: ignore
    RateLimiterBackend = None  # type: ignore
    build_backend = None  # type: ignore

def _now() -> float:
    return _monotonic()


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

RATE_LIMIT_SKIPS = _get_or_create_metric(
    Counter,
    "guardrail_rate_limit_skipped_total",
    "Total number of requests skipped by rate limiting",
    labelnames=("reason",),
)


class RateLimiter:
    def __init__(
        self,
        capacity: float,
        refill_rate: float,
        backend: Optional[RateLimiterBackend] = None,
    ) -> None:
        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate)
        if backend is None:
            if LocalTokenBucket is not None:
                backend = LocalTokenBucket()
            else:  # pragma: no cover - fallback for import failures
                raise RuntimeError("LocalTokenBucket backend unavailable")
        if hasattr(backend, "set_now"):
            try:
                backend.set_now(_now)
            except Exception:  # pragma: no cover - defensive
                pass
        self._backend = backend

    def allow(self, tenant: str, bot: str, cost: float = 1.0) -> Tuple[bool, Optional[int], float]:
        key = f"{tenant}:{bot}"
        allowed, retry_after_seconds, remaining = self._backend.allow(
            key,
            cost=cost,
            rps=self.refill_rate,
            burst=self.capacity,
        )

        retry_after: Optional[int]
        if allowed or retry_after_seconds <= 0:
            retry_after = None
        else:
            retry_after = max(1, int(math.ceil(retry_after_seconds)))

        if remaining is not None:
            try:
                TOKENS_GAUGE.labels(tenant=tenant, bot=bot).set(max(0.0, remaining))
            except Exception:
                pass

        return allowed, retry_after, float(remaining or 0.0)


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
    """
    Reads settings if available:
      settings.ingress.rate_limit.enabled (bool)
      settings.ingress.rate_limit.rps (float)
      settings.ingress.rate_limit.burst (float)
    Fallback env:
      RATE_LIMIT_ENABLED (default: false)
      RATE_LIMIT_RPS (default: 5.0)
      RATE_LIMIT_BURST (default: 10.0)
    """
    enabled_default = False  # opt-in
    rps_default = 5.0
    burst_default = 10.0

    enabled = enabled_default
    rps = rps_default
    burst = burst_default

    try:
        rl = getattr(getattr(settings, "ingress"), "rate_limit", None)
        if rl is not None:
            enabled = bool(getattr(rl, "enabled", enabled_default))
            rps = float(getattr(rl, "rps", rps_default))
            burst = float(getattr(rl, "burst", burst_default))
        else:
            enabled = _bool_env("RATE_LIMIT_ENABLED", enabled_default)
            rps = _float_env("RATE_LIMIT_RPS", rps_default)
            burst = _float_env("RATE_LIMIT_BURST", burst_default)
    except Exception:
        enabled = _bool_env("RATE_LIMIT_ENABLED", enabled_default)
        rps = _float_env("RATE_LIMIT_RPS", rps_default)
        burst = _float_env("RATE_LIMIT_BURST", burst_default)

    backend_instance: Optional[RateLimiterBackend] = None
    if build_backend is not None:
        try:
            backend_instance = build_backend()
        except Exception:
            backend_instance = None

    return enabled, RateLimiter(
        capacity=burst,
        refill_rate=rps,
        backend=backend_instance,
    )


_global_enforce_unknown: Optional[bool] = None
_global_enforce_unknown_source: Optional[str] = None


def _enforce_unknown_from_settings(settings) -> bool:
    """Read enforcement policy for 'unknown' identities."""

    try:
        ingress = getattr(settings, "ingress", None)
        if ingress is not None:
            rl = getattr(ingress, "rate_limit", None)
            if rl is not None and hasattr(rl, "enforce_unknown"):
                return bool(getattr(rl, "enforce_unknown"))
    except Exception:
        pass
    return _bool_env("RATE_LIMIT_ENFORCE_UNKNOWN", False)


def get_enforce_unknown(settings=None) -> bool:
    global _global_enforce_unknown, _global_enforce_unknown_source

    settings = getattr(settings, "value", settings)

    if settings is not None:
        value = _enforce_unknown_from_settings(settings)
        _global_enforce_unknown = value
        _global_enforce_unknown_source = "__settings__"
        return value

    current_env = os.getenv("RATE_LIMIT_ENFORCE_UNKNOWN")
    if (
        _global_enforce_unknown is not None
        and _global_enforce_unknown_source == current_env
    ):
        return _global_enforce_unknown

    value = _enforce_unknown_from_settings(settings)
    _global_enforce_unknown = value
    _global_enforce_unknown_source = current_env
    return value


_global_enabled: Optional[bool] = None
_global_limiter: Optional[RateLimiter] = None


def get_global(settings=None) -> Tuple[bool, RateLimiter]:
    global _global_enabled, _global_limiter
    if _global_limiter is not None and _global_enabled is not None:
        return _global_enabled, _global_limiter
    enabled, limiter = build_from_settings(getattr(settings, "value", settings))
    _global_enabled, _global_limiter = enabled, limiter
    return enabled, limiter

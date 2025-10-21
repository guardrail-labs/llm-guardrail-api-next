from __future__ import annotations

import math
import os
import time
from typing import Optional, Tuple

from prometheus_client import REGISTRY, Counter, Gauge

try:  # pragma: no cover - defensive import; tests exercise real path
    from app.services.ratelimit_backends import (
        LocalTokenBucket,
        RateLimiterBackend,
        build_backend,
    )
except Exception:  # pragma: no cover
    LocalTokenBucket = None  # type: ignore
    RateLimiterBackend = None  # type: ignore
    build_backend = None  # type: ignore

# Tests monkeypatch this to freeze time in burst scenarios.
_NOW = time.monotonic


def _now() -> float:
    return _NOW()


def _get_or_create_metric(factory, name: str, documentation: str, **kwargs):
    """
    Prometheus helper that tolerates re-registration across tests.
    """
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
        # Allow tests to override the internal clock by setting _NOW.
        if hasattr(backend, "set_now"):
            try:
                backend.set_now(_now)
            except Exception:  # pragma: no cover
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
        if allowed or (retry_after_seconds or 0) <= 0:
            retry_after = None
        else:
            retry_after = max(1, int(math.ceil(float(retry_after_seconds))))

        if remaining is not None:
            try:
                TOKENS_GAUGE.labels(tenant=tenant, bot=bot).set(max(0.0, float(remaining)))
            except Exception:
                pass

        return allowed, retry_after, float(remaining or 0.0)


# ------------------------------ Settings helpers -----------------------------


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "t", "yes", "on"}


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
        rl = getattr(getattr(settings, "ingress", None), "rate_limit", None)
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


# ------------------- Unknown-identity enforcement policy ---------------------

_global_enforce_unknown: Optional[bool] = None
_global_enforce_unknown_source: Optional[str] = None


def _enforce_unknown_from_settings(settings) -> bool:
    try:
        ingress = getattr(settings, "ingress", None)
        rl = getattr(ingress, "rate_limit", None) if ingress is not None else None
        if rl is not None and hasattr(rl, "enforce_unknown"):
            return bool(getattr(rl, "enforce_unknown"))
    except Exception:
        pass
    return _bool_env("RATE_LIMIT_ENFORCE_UNKNOWN", False)


def get_enforce_unknown(settings=None) -> bool:
    """
    Cache with invalidation when env var changes. When settings are provided,
    prefer them and refresh the cache each call (tests pass settings directly).
    """
    global _global_enforce_unknown, _global_enforce_unknown_source

    settings = getattr(settings, "value", settings)

    if settings is not None:
        val = _enforce_unknown_from_settings(settings)
        _global_enforce_unknown = val
        _global_enforce_unknown_source = "__settings__"
        return val

    current_env = os.getenv("RATE_LIMIT_ENFORCE_UNKNOWN", "")
    if (
        _global_enforce_unknown is not None
        and _global_enforce_unknown_source == current_env
    ):
        return _global_enforce_unknown

    val = _enforce_unknown_from_settings(settings)
    _global_enforce_unknown = val
    _global_enforce_unknown_source = current_env
    return val


# ---------------------------- Global limiter cache ---------------------------

_global_cfg: Optional[tuple] = None
_global_enabled: Optional[bool] = None
_global_limiter: Optional[RateLimiter] = None


def _config_tuple(enabled: bool, limiter: RateLimiter) -> tuple:
    return (bool(enabled), float(limiter.refill_rate), float(limiter.capacity))


def get_global(settings=None) -> Tuple[bool, RateLimiter]:
    """
    Returns a (enabled, RateLimiter) pair. Rebuilds the limiter whenever
    settings/env change so tests that flip env vars between runs see updates.
    """
    global _global_cfg, _global_enabled, _global_limiter

    enabled, limiter = build_from_settings(getattr(settings, "value", settings))
    new_cfg = _config_tuple(enabled, limiter)

    if _global_cfg != new_cfg or _global_limiter is None:
        # Always propagate the current _now to the backend (important when tests
        # monkeypatch _NOW to freeze time).
        if hasattr(limiter._backend, "set_now"):
            try:
                limiter._backend.set_now(_now)
            except Exception:
                pass
        _global_cfg = new_cfg
        _global_enabled = enabled
        _global_limiter = limiter

    return _global_enabled, _global_limiter  # type: ignore[return-value]

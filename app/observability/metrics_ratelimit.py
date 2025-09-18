from __future__ import annotations

import os

try:  # pragma: no cover
    from prometheus_client import Counter, Gauge
except Exception:  # pragma: no cover
    Counter = Gauge = None  # type: ignore

try:  # pragma: no cover
    from app.observability.metrics import (
        guardrail_ratelimit_redis_script_reload_total,
    )
except Exception:  # pragma: no cover
    guardrail_ratelimit_redis_script_reload_total = None  # type: ignore

_ENABLED = os.getenv("METRICS_ENABLED", "true").lower() in ("1", "true", "yes", "on")

_ctr_error = None
_ctr_fallback = None
_g_backend = None
_init_done = False


def _counters():
    global _ctr_error, _ctr_fallback
    if not _ENABLED or Counter is None:
        return None, None, None
    if _ctr_error is None:
        _ctr_error = Counter(
            "guardrail_ratelimit_redis_errors_total",
            "Redis rate-limit errors by type",
            ["type"],
        )
    if _ctr_fallback is None:
        _ctr_fallback = Counter(
            "guardrail_ratelimit_fallback_total",
            "Rate-limit fallbacks to local backend",
            ["reason"],
        )
    return guardrail_ratelimit_redis_script_reload_total, _ctr_error, _ctr_fallback


def inc_script_reload() -> None:
    counter, _, _ = _counters()
    if counter:
        try:
            counter.inc()
        except Exception:
            pass


def inc_error(kind: str) -> None:
    _, counter, _ = _counters()
    if counter:
        try:
            counter.labels(type=kind or "other").inc()
        except Exception:
            pass


def inc_fallback(reason: str) -> None:
    _, _, counter = _counters()
    if counter:
        try:
            counter.labels(reason=reason or "error").inc()
        except Exception:
            pass


def set_backend_in_use(name: str) -> None:
    global _g_backend, _init_done
    if _init_done or not _ENABLED or Gauge is None:
        return
    try:
        _g_backend = Gauge(
            "guardrail_ratelimit_backend_in_use",
            "Which rate-limit backend is active (1=active)",
            ["backend"],
        )
        _g_backend.labels(backend=name or "local").set(1)
        _init_done = True
    except Exception:
        pass

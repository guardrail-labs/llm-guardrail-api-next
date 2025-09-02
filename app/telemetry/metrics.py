from __future__ import annotations

import logging
from types import SimpleNamespace
from typing import Any, Dict, Optional

log = logging.getLogger(__name__)

try:
    # Normal case: prometheus is installed
    from prometheus_client import Counter as _Counter
    from prometheus_client import Histogram as _Histogram
    from prometheus_client import REGISTRY as _REGISTRY
except Exception:
    # Fallback: no prometheus, supply minimal no-op shims
    class _Counter:  # noqa: D401 - minimal surface for mypy/runtime
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            ...

        def inc(self, *args: Any, **kwargs: Any) -> None:
            ...

        def labels(self, *args: Any, **kwargs: Any) -> _Counter:
            return self

    class _Histogram:  # noqa: D401
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            ...

        def observe(self, *args: Any, **kwargs: Any) -> None:
            ...

        def labels(self, *args: Any, **kwargs: Any) -> _Histogram:
            return self

    # Registry stub with a dict attribute
    _REGISTRY = SimpleNamespace(_names_to_collectors={})

# Export names expected by the rest of the codebase
Counter = _Counter
Histogram = _Histogram
REGISTRY = _REGISTRY


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def get_metric(name: str) -> Optional[Any]:
    """
    Return a registered metric collector by name, or None if not present.
    Safe to call even when using fallback shims.
    """
    return getattr(REGISTRY, "_names_to_collectors", {}).get(name)


# Example: define metrics centrally here so they’re only registered once
guardrail_requests_total = Counter(
    "guardrail_requests_total",
    "Total number of guardrail requests",
    ["endpoint"],
)

guardrail_decisions_total = Counter(
    "guardrail_decisions_total",
    "Total number of guardrail decisions",
    ["action"],
)

guardrail_latency_seconds = Histogram(
    "guardrail_latency_seconds",
    "Latency of guardrail API requests",
    ["endpoint"],
)


def observe_request_latency(endpoint: str, duration: float) -> None:
    """
    Record latency for an endpoint in seconds.
    Safe to call with fallback Histogram.
    """
    try:
        guardrail_latency_seconds.labels(endpoint=endpoint).observe(duration)
    except Exception as exc:  # pragma: no cover
        log.debug("Failed to observe latency: %s", exc)


def increment_request(endpoint: str) -> None:
    """
    Increment request counter for an endpoint.
    """
    try:
        guardrail_requests_total.labels(endpoint=endpoint).inc()
    except Exception as exc:  # pragma: no cover
        log.debug("Failed to increment request counter: %s", exc)


def increment_decision(action: str) -> None:
    """
    Increment decision counter for an action.
    """
    try:
        guardrail_decisions_total.labels(action=action).inc()
    except Exception as exc:  # pragma: no cover
        log.debug("Failed to increment decision counter: %s", exc)


# Optional: expose all current metrics as a dict for debugging
def dump_metrics() -> Dict[str, Any]:
    """
    Return a mapping of metric names to collectors currently in the registry.
    """
    try:
        return dict(getattr(REGISTRY, "_names_to_collectors", {}))
    except Exception:
        return {}

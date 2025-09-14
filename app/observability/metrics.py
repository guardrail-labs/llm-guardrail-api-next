from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Sequence, Tuple

# Prometheus optional; keep callers safe if not installed.
try:  # pragma: no cover
    from prometheus_client import (
        REGISTRY,
        CollectorRegistry,
        Counter,
        Gauge,
        Histogram,
    )
    _HAVE_PROM = True
except Exception:  # pragma: no cover
    REGISTRY = None  # type: ignore[assignment]
    _HAVE_PROM = False

    class CollectorRegistry:  # type: ignore[no-redef]
        ...

    class _BaseMetric:
        def labels(self, **_kw: str) -> "_BaseMetric":
            return self

    class Counter(_BaseMetric):  # type: ignore[no-redef]
        def __init__(self, *args: Any, **kwargs: Any) -> None: ...
        def inc(self, *_a: Any, **_kw: Any) -> None: ...

    class Gauge(_BaseMetric):  # type: ignore[no-redef]
        def __init__(self, *args: Any, **kwargs: Any) -> None: ...
        def set(self, *_a: Any, **_kw: Any) -> None: ...

    class Histogram(_BaseMetric):  # type: ignore[no-redef]
        def __init__(self, *args: Any, **kwargs: Any) -> None: ...
        def observe(self, *_a: Any, **_kw: Any) -> None: ...


# -------- Verifier provider metrics (existing/compatible) ---------------------

@dataclass(frozen=True)
class VerifierMetrics:
    sampled_total: Any
    skipped_total: Any
    timeout_total: Any
    duration_seconds: Any
    circuit_open_total: Any
    error_total: Any
    circuit_state: Any | None


def _get_from_registry(name: str) -> Optional[Any]:
    try:
        reg = REGISTRY
        names_map = getattr(reg, "_names_to_collectors", None)
        if isinstance(names_map, dict):
            return names_map.get(name)
    except Exception:
        return None
    return None


def make_verifier_metrics(registry: Any) -> VerifierMetrics:
    if not _HAVE_PROM or registry is None:  # pragma: no cover
        return VerifierMetrics(None, None, None, None, None, None, None)

    def _counter(name: str, help_: str, labels: Sequence[str]) -> Any:
        try:
            return Counter(name, help_, labelnames=tuple(labels), registry=registry)
        except Exception:
            existing = _get_from_registry(name)
            if existing is not None:
                return existing
            raise

    def _hist(
        name: str,
        help_: str,
        labels: Sequence[str],
        buckets: Tuple[float, ...],
    ) -> Any:
        try:
            return Histogram(
                name,
                help_,
                labelnames=tuple(labels),
                registry=registry,
                buckets=buckets,
            )
        except Exception:
            existing = _get_from_registry(name)
            if existing is not None:
                return existing
            raise

    def _gauge(name: str, help_: str, labels: Sequence[str]) -> Any:
        try:
            return Gauge(name, help_, labelnames=tuple(labels), registry=registry)
        except Exception:
            existing = _get_from_registry(name)
            if existing is not None:
                return existing
            return None

    sampled = _counter(
        "guardrail_verifier_sampled_total",
        "Count of requests for which the verifier was invoked (sampled).",
        ("provider",),
    )
    skipped = _counter(
        "guardrail_verifier_skipped_total",
        "Count of requests skipped by sampling gate (not verified).",
        ("provider",),
    )
    timeout = _counter(
        "guardrail_verifier_timeout_total",
        "Count of verifier calls that exceeded the latency budget.",
        ("provider",),
    )
    circuit_open = _counter(
        "guardrail_verifier_circuit_open_total",
        "Count of calls skipped because the circuit breaker was open.",
        ("provider",),
    )
    errors = _counter(
        "guardrail_verifier_provider_error_total",
        "Count of verifier provider exceptions (excluding timeouts).",
        ("provider",),
    )
    duration = _hist(
        "guardrail_verifier_duration_seconds",
        "Time spent in provider evaluation (successful or timed out).",
        ("provider",),
        buckets=(
            0.001,
            0.005,
            0.01,
            0.025,
            0.05,
            0.1,
            0.25,
            0.5,
            1.0,
            2.5,
            5.0,
            10.0,
        ),
    )
    circuit_state = _gauge(
        "guardrail_verifier_circuit_state",
        "State of verifier circuit breaker (1=open, 0=closed).",
        ("provider",),
    )

    return VerifierMetrics(
        sampled_total=sampled,
        skipped_total=skipped,
        timeout_total=timeout,
        duration_seconds=duration,
        circuit_open_total=circuit_open,
        error_total=errors,
        circuit_state=circuit_state,
    )


VERIFIER_METRICS: VerifierMetrics = make_verifier_metrics(REGISTRY)


# -------- Clarify / egress counters (existing) --------------------------------

if _HAVE_PROM:
    GUARDRAIL_CLARIFY_TOTAL: Optional[Any] = Counter(
        "guardrail_clarify_total",
        "Total clarify-first decisions",
        ["phase"],
        registry=REGISTRY,
    )
    GUARDRAIL_EGRESS_REDACTIONS_TOTAL: Optional[Any] = Counter(
        "guardrail_egress_redactions_total",
        "Total egress redactions applied",
        ["content_type"],
        registry=REGISTRY,
    )
else:  # pragma: no cover
    GUARDRAIL_CLARIFY_TOTAL = None
    GUARDRAIL_EGRESS_REDACTIONS_TOTAL = None


def inc_clarify(phase: str = "ingress") -> None:
    try:
        if GUARDRAIL_CLARIFY_TOTAL is not None:
            GUARDRAIL_CLARIFY_TOTAL.labels(phase=phase).inc()
    except Exception:
        pass


def inc_egress_redactions(content_type: str, n: int = 1) -> None:
    if n <= 0:
        return
    try:
        if GUARDRAIL_EGRESS_REDACTIONS_TOTAL is not None:
            GUARDRAIL_EGRESS_REDACTIONS_TOTAL.labels(content_type=content_type).inc(n)
    except Exception:
        pass


# -------- Soft counter helper + router rank counter ---------------------------

_COUNTER_LABELS: Dict[str, Tuple[str, ...]] = {}
_COUNTERS: Dict[str, Any] = {}


def inc_counter(name: str, labels: Dict[str, str]) -> None:
    """
    Soft-hook counter increment that registers on the same REGISTRY
    as /metrics. Creates the counter on first use; subsequent calls reuse it.
    """
    if not _HAVE_PROM or REGISTRY is None:  # pragma: no cover
        return

    try:
        lbls = tuple(sorted(labels.keys()))
        existing = _COUNTERS.get(name)
        if existing is None:
            schema = _COUNTER_LABELS.setdefault(name, lbls)
            ctr = _get_from_registry(name)
            if ctr is None:
                ctr = Counter(
                    name,
                    name.replace("_", " "),
                    labelnames=schema,
                    registry=REGISTRY,
                )
            _COUNTERS[name] = ctr
        else:
            schema = _COUNTER_LABELS.get(name, lbls)
            if lbls != schema:
                return
            ctr = existing

        ctr.labels(**labels).inc()
    except Exception:
        # Never fail the request path due to metrics.
        pass


def inc_verifier_router_rank(tenant: str, bot: str) -> None:
    inc_counter("verifier_router_rank_total", {"tenant": tenant, "bot": bot})

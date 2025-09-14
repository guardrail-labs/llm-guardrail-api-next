from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Optional, cast

from prometheus_client import (
    REGISTRY,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
)


# ------------------------- Helper: idempotent collectors -------------------------

def _existing_collector(
    registry: CollectorRegistry, name: str
) -> Any | None:
    """Return an existing collector by name if available."""
    try:
        return getattr(registry, "_names_to_collectors", {}).get(name)
    except Exception:
        return None


def _get_or_create_counter(
    registry: CollectorRegistry,
    name: str,
    documentation: str,
    labelnames: Iterable[str] | None = None,
) -> Counter:
    labelnames = tuple(labelnames or ())
    existing = _existing_collector(registry, name)
    if isinstance(existing, Counter):
        return cast(Counter, existing)
    try:
        return Counter(
            name,
            documentation,
            labelnames=labelnames,
            registry=registry,
        )
    except Exception:
        # If a concurrent import/registration won the race, fetch it.
        existing = _existing_collector(registry, name)
        if isinstance(existing, Counter):
            return cast(Counter, existing)
        raise


def _get_or_create_gauge(
    registry: CollectorRegistry,
    name: str,
    documentation: str,
    labelnames: Iterable[str] | None = None,
) -> Gauge:
    labelnames = tuple(labelnames or ())
    existing = _existing_collector(registry, name)
    if isinstance(existing, Gauge):
        return cast(Gauge, existing)
    try:
        return Gauge(
            name,
            documentation,
            labelnames=labelnames,
            registry=registry,
        )
    except Exception:
        existing = _existing_collector(registry, name)
        if isinstance(existing, Gauge):
            return cast(Gauge, existing)
        raise


def _get_or_create_histogram(
    registry: CollectorRegistry,
    name: str,
    documentation: str,
    labelnames: Iterable[str] | None = None,
    buckets: Iterable[float] | None = None,
) -> Histogram:
    labelnames = tuple(labelnames or ())
    buckets = tuple(buckets or ())
    existing = _existing_collector(registry, name)
    if isinstance(existing, Histogram):
        return cast(Histogram, existing)
    try:
        return Histogram(
            name,
            documentation,
            labelnames=labelnames,
            registry=registry,
            buckets=buckets,
        )
    except Exception:
        existing = _existing_collector(registry, name)
        if isinstance(existing, Histogram):
            return cast(Histogram, existing)
        raise


# ------------------------------ Verifier metrics -------------------------------

@dataclass(frozen=True)
class VerifierMetrics:
    sampled_total: Counter
    skipped_total: Counter
    timeout_total: Counter
    duration_seconds: Histogram  # labeled by provider
    circuit_open_total: Counter
    error_total: Counter
    circuit_state: Gauge | None


def make_verifier_metrics(registry: CollectorRegistry) -> VerifierMetrics:
    sampled = _get_or_create_counter(
        registry,
        "guardrail_verifier_sampled_total",
        "Count of requests for which the verifier was invoked (sampled).",
        labelnames=("provider",),
    )
    skipped = _get_or_create_counter(
        registry,
        "guardrail_verifier_skipped_total",
        "Count of requests skipped by sampling gate (not verified).",
        labelnames=("provider",),
    )
    timeout = _get_or_create_counter(
        registry,
        "guardrail_verifier_timeout_total",
        "Count of verifier calls that exceeded the latency budget.",
        labelnames=("provider",),
    )
    circuit_open = _get_or_create_counter(
        registry,
        "guardrail_verifier_circuit_open_total",
        "Count of calls skipped because the circuit breaker was open.",
        labelnames=("provider",),
    )
    errors = _get_or_create_counter(
        registry,
        "guardrail_verifier_provider_error_total",
        "Count of verifier provider exceptions (excluding timeouts).",
        labelnames=("provider",),
    )
    duration = _get_or_create_histogram(
        registry,
        "guardrail_verifier_duration_seconds",
        "Time spent in provider evaluation (successful or timed out).",
        labelnames=("provider",),
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

    # Gauge may be unsupported in some environments; guard it.
    try:
        circuit_state = _get_or_create_gauge(
            registry,
            "guardrail_verifier_circuit_state",
            "State of verifier circuit breaker (1=open, 0=closed).",
            labelnames=("provider",),
        )
    except Exception:  # pragma: no cover
        circuit_state = None

    return VerifierMetrics(
        sampled_total=sampled,
        skipped_total=skipped,
        timeout_total=timeout,
        duration_seconds=duration,
        circuit_open_total=circuit_open,
        error_total=errors,
        circuit_state=circuit_state,
    )


# Default metrics used by the app (register on the global REGISTRY)
VERIFIER_METRICS: VerifierMetrics = make_verifier_metrics(REGISTRY)


# ------------------------- Other guardrail-wide counters -----------------------

# Register on the same REGISTRY the /metrics route scrapes.
GUARDRAIL_CLARIFY_TOTAL = _get_or_create_counter(
    REGISTRY,
    "guardrail_clarify_total",
    "Total clarify-first decisions",
    ("phase",),
)

GUARDRAIL_EGRESS_REDACTIONS_TOTAL = _get_or_create_counter(
    REGISTRY,
    "guardrail_egress_redactions_total",
    "Total egress redactions applied",
    ("content_type",),
)

# Also expose a shared counter the router uses/tests assert on.
VERIFIER_ROUTER_RANK_TOTAL = _get_or_create_counter(
    REGISTRY,
    "verifier_router_rank_total",
    "Count of provider rank computations by tenant and bot.",
    ("tenant", "bot"),
)


def inc_clarify(phase: str = "ingress") -> None:
    GUARDRAIL_CLARIFY_TOTAL.labels(phase=phase).inc()


def inc_egress_redactions(content_type: str, n: int = 1) -> None:
    if n > 0:
        GUARDRAIL_EGRESS_REDACTIONS_TOTAL.labels(content_type=content_type).inc(n)


def inc_verifier_router_rank(tenant: str, bot: str, n: int = 1) -> None:
    if n > 0:
        VERIFIER_ROUTER_RANK_TOTAL.labels(tenant=tenant, bot=bot).inc(n)

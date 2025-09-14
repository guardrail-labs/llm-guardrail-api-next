from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

from prometheus_client import (
    REGISTRY,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
)


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
    sampled = Counter(
        "guardrail_verifier_sampled_total",
        "Count of requests for which the verifier was invoked (sampled).",
        labelnames=("provider",),
        registry=registry,
    )
    skipped = Counter(
        "guardrail_verifier_skipped_total",
        "Count of requests skipped by sampling gate (not verified).",
        labelnames=("provider",),
        registry=registry,
    )
    timeout = Counter(
        "guardrail_verifier_timeout_total",
        "Count of verifier calls that exceeded the latency budget.",
        labelnames=("provider",),
        registry=registry,
    )
    circuit_open = Counter(
        "guardrail_verifier_circuit_open_total",
        "Count of calls skipped because the circuit breaker was open.",
        labelnames=("provider",),
        registry=registry,
    )
    errors = Counter(
        "guardrail_verifier_provider_error_total",
        "Count of verifier provider exceptions (excluding timeouts).",
        labelnames=("provider",),
        registry=registry,
    )
    duration = Histogram(
        "guardrail_verifier_duration_seconds",
        "Time spent in provider evaluation (successful or timed out).",
        labelnames=("provider",),
        registry=registry,
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
    try:
        circuit_state = Gauge(
            "guardrail_verifier_circuit_state",
            "State of verifier circuit breaker (1=open, 0=closed).",
            labelnames=("provider",),
            registry=registry,
        )
    except Exception:  # pragma: no cover - Gauge may be unavailable
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


# Default metrics used by the app
VERIFIER_METRICS: VerifierMetrics = make_verifier_metrics(REGISTRY)


# ---- Clarify / egress counters ----------------------------------------------

# Counters are safe to import multiple times; prometheus_client caches by name.
GUARDRAIL_CLARIFY_TOTAL = Counter(
    "guardrail_clarify_total",
    "Total clarify-first decisions",
    ["phase"],
)

GUARDRAIL_EGRESS_REDACTIONS_TOTAL = Counter(
    "guardrail_egress_redactions_total",
    "Total egress redactions applied",
    ["content_type"],
)


def inc_clarify(phase: str = "ingress") -> None:
    GUARDRAIL_CLARIFY_TOTAL.labels(phase=phase).inc()


def inc_egress_redactions(content_type: str, n: int = 1) -> None:
    if n > 0:
        GUARDRAIL_EGRESS_REDACTIONS_TOTAL.labels(content_type=content_type).inc(n)


_COUNTERS: Dict[str, Counter] = {}


def inc_counter(name: str, labels: Dict[str, str]) -> None:
    try:
        from app.routes.metrics import REGISTRY as route_registry  # type: ignore
    except Exception:
        route_registry = None
    from prometheus_client import REGISTRY as default_registry

    registry = route_registry or default_registry

    counter = _COUNTERS.get(name)
    registry_counters = getattr(registry, "_names_to_collectors", {})
    if counter is None or counter not in registry_counters.values():
        try:
            counter = Counter(name, name, list(labels.keys()), registry=registry)
        except ValueError:
            counter = registry_counters.get(name) if isinstance(registry_counters, dict) else None
            if counter is None:
                return
        _COUNTERS[name] = counter
    try:
        counter.labels(**labels).inc()
    except Exception:
        pass

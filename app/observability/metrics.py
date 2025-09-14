from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional, Set, Tuple

from prometheus_client import REGISTRY, CollectorRegistry, Counter, Gauge, Histogram

_METRICS_LABEL_CARD_MAX = int(
    os.getenv("METRICS_LABEL_CARDINALITY_MAX", "1000") or "1000"
)
_METRICS_LABEL_OVERFLOW = os.getenv("METRICS_LABEL_OVERFLOW", "overflow")

_seen_tenants: Set[str] = set()
_seen_bots: Set[str] = set()


def _safe_label(val: str, cache: Set[str]) -> str:
    if not val:
        return "unknown"
    if val in cache:
        return val
    if len(cache) < _METRICS_LABEL_CARD_MAX:
        cache.add(val)
        return val
    return _METRICS_LABEL_OVERFLOW


def _limit_tenant_bot_labels(tenant: str, bot: str) -> Tuple[str, str]:
    return _safe_label(str(tenant), _seen_tenants), _safe_label(
        str(bot), _seen_bots
    )


# ---- Helpers to avoid duplicate registration ---------------------------------


def _get_or_create_counter(
    name: str,
    doc: str,
    labelnames: Tuple[str, ...] = (),
    registry: Optional[CollectorRegistry] = None,
) -> Counter:
    reg = registry or REGISTRY
    # Try to reuse an existing collector if already registered.
    try:
        names_map = getattr(reg, "_names_to_collectors", None)
        if isinstance(names_map, dict):
            existing = names_map.get(name)
            if isinstance(existing, Counter):
                return existing
    except Exception:
        pass

    try:
        return Counter(name, doc, labelnames=labelnames, registry=reg)
    except ValueError:
        # Another module created it first; fetch and reuse.
        try:
            names_map = getattr(reg, "_names_to_collectors", None)
            if isinstance(names_map, dict):
                found = names_map.get(name)
                if isinstance(found, Counter):
                    return found
        except Exception:
            pass
        # Final fallback: create an unregistered counter (won't be exposed).
        return Counter(name, doc, labelnames=labelnames)


def _get_or_create_histogram(
    name: str,
    doc: str,
    labelnames: Tuple[str, ...] = (),
    registry: Optional[CollectorRegistry] = None,
    buckets: Tuple[float, ...] = (),
) -> Histogram:
    reg = registry or REGISTRY
    try:
        names_map = getattr(reg, "_names_to_collectors", None)
        if isinstance(names_map, dict):
            existing = names_map.get(name)
            if isinstance(existing, Histogram):
                return existing
    except Exception:
        pass

    try:
        return Histogram(
            name,
            doc,
            labelnames=labelnames,
            registry=reg,
            buckets=buckets or Histogram.DEFAULT_BUCKETS,
        )
    except ValueError:
        try:
            names_map = getattr(reg, "_names_to_collectors", None)
            if isinstance(names_map, dict):
                found = names_map.get(name)
                if isinstance(found, Histogram):
                    return found
        except Exception:
            pass
        return Histogram(name, doc, labelnames=labelnames)


def _get_or_create_gauge(
    name: str,
    doc: str,
    labelnames: Tuple[str, ...] = (),
    registry: Optional[CollectorRegistry] = None,
) -> Gauge:
    reg = registry or REGISTRY
    try:
        names_map = getattr(reg, "_names_to_collectors", None)
        if isinstance(names_map, dict):
            existing = names_map.get(name)
            if isinstance(existing, Gauge):
                return existing
    except Exception:
        pass

    try:
        return Gauge(name, doc, labelnames=labelnames, registry=reg)
    except ValueError:
        try:
            names_map = getattr(reg, "_names_to_collectors", None)
            if isinstance(names_map, dict):
                found = names_map.get(name)
                if isinstance(found, Gauge):
                    return found
        except Exception:
            pass
        return Gauge(name, doc, labelnames=labelnames)


# ---- Verifier provider metrics (existing set) --------------------------------


@dataclass(frozen=True)
class VerifierMetrics:
    sampled_total: Counter
    skipped_total: Counter
    timeout_total: Counter
    duration_seconds: Histogram  # labeled by provider
    circuit_open_total: Counter
    error_total: Counter
    circuit_state: Optional[Gauge]


def make_verifier_metrics(registry: CollectorRegistry) -> VerifierMetrics:
    sampled = _get_or_create_counter(
        "guardrail_verifier_sampled_total",
        "Count of requests for which the verifier was invoked (sampled).",
        labelnames=("provider",),
        registry=registry,
    )
    skipped = _get_or_create_counter(
        "guardrail_verifier_skipped_total",
        "Count of requests skipped by sampling gate (not verified).",
        labelnames=("provider",),
        registry=registry,
    )
    timeout = _get_or_create_counter(
        "guardrail_verifier_timeout_total",
        "Count of verifier calls that exceeded the latency budget.",
        labelnames=("provider",),
        registry=registry,
    )
    circuit_open = _get_or_create_counter(
        "guardrail_verifier_circuit_open_total",
        "Count of calls skipped because the circuit breaker was open.",
        labelnames=("provider",),
        registry=registry,
    )
    errors = _get_or_create_counter(
        "guardrail_verifier_provider_error_total",
        "Count of verifier provider exceptions (excluding timeouts).",
        labelnames=("provider",),
        registry=registry,
    )
    duration = _get_or_create_histogram(
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
        circuit_state = _get_or_create_gauge(
            "guardrail_verifier_circuit_state",
            "State of verifier circuit breaker (1=open, 0=closed).",
            labelnames=("provider",),
            registry=registry,
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


# Singleton (safe due to get_or_create semantics)
VERIFIER_METRICS: VerifierMetrics = make_verifier_metrics(REGISTRY)


# ---- Clarify / egress counters (existing) ------------------------------------

GUARDRAIL_CLARIFY_TOTAL = _get_or_create_counter(
    "guardrail_clarify_total",
    "Total clarify-first decisions",
    ("phase",),
)

GUARDRAIL_EGRESS_REDACTIONS_TOTAL = _get_or_create_counter(
    "guardrail_egress_redactions_total",
    "Total egress redactions applied",
    ("tenant", "bot", "kind"),
)


def inc_clarify(phase: str = "ingress") -> None:
    GUARDRAIL_CLARIFY_TOTAL.labels(phase=phase).inc()


def inc_egress_redactions(tenant: str, bot: str, kind: str, n: int = 1) -> None:
    if n > 0:
        tenant_l, bot_l = _limit_tenant_bot_labels(tenant, bot)
        try:
            GUARDRAIL_EGRESS_REDACTIONS_TOTAL.labels(
                tenant=tenant_l, bot=bot_l, kind=kind
            ).inc(n)
        except Exception:
            pass


# ---- Verifier router rank metric (Hybrid-12) ---------------------------------

VERIFIER_ROUTER_RANK_TOTAL = _get_or_create_counter(
    "verifier_router_rank_total",
    "Count of provider rank computations by tenant and bot.",
    ("tenant", "bot"),
    registry=REGISTRY,
)


def inc_verifier_router_rank(tenant: str, bot: str) -> None:
    """
    Increment the rank counter with canonical label set. Registered on REGISTRY,
    which your /metrics route exports.
    """
    tenant_l, bot_l = _limit_tenant_bot_labels(tenant, bot)
    try:
        VERIFIER_ROUTER_RANK_TOTAL.labels(tenant=tenant_l, bot=bot_l).inc()
    except Exception:
        pass

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional, Set, Tuple

from prometheus_client import REGISTRY, CollectorRegistry, Counter, Gauge, Histogram

_CARD_MAX_RAW = (
    os.getenv("METRICS_LABEL_CARD_MAX")
    or os.getenv("METRICS_LABEL_CARDINALITY_MAX")
    or "1000"
)
_METRICS_LABEL_CARD_MAX = int(_CARD_MAX_RAW or "1000")
_PAIR_MAX_RAW = (
    os.getenv("METRICS_LABEL_PAIR_CARD_MAX")
    or os.getenv("METRICS_LABEL_PAIR_CARDINALITY_MAX")
    or str(_METRICS_LABEL_CARD_MAX)
)
_METRICS_LABEL_PAIR_CARD_MAX = int(_PAIR_MAX_RAW or str(_METRICS_LABEL_CARD_MAX))
_METRICS_LABEL_OVERFLOW = os.getenv("METRICS_LABEL_OVERFLOW", "__overflow__")

_seen_tenants: Set[str] = set()
_seen_bots: Set[str] = set()
_seen_pairs: Set[Tuple[str, str]] = set()


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
    tenant_l = _safe_label(str(tenant), _seen_tenants)
    bot_l = _safe_label(str(bot), _seen_bots)
    if _METRICS_LABEL_OVERFLOW in {tenant_l, bot_l}:
        return _METRICS_LABEL_OVERFLOW, _METRICS_LABEL_OVERFLOW
    pair = (tenant_l, bot_l)
    if pair in _seen_pairs:
        return pair
    if len(_seen_pairs) < _METRICS_LABEL_PAIR_CARD_MAX:
        _seen_pairs.add(pair)
        return pair
    return _METRICS_LABEL_OVERFLOW, _METRICS_LABEL_OVERFLOW


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


GUARDRAIL_RATELIMIT_REDIS_SCRIPT_RELOAD_TOTAL = _get_or_create_counter(
    "guardrail_ratelimit_redis_script_reload_total",
    "Count of Redis rate-limit Lua reloads triggered by NOSCRIPT.",
)


webhook_retry_total = _get_or_create_counter(
    "guardrail_webhook_retry_total",
    "Webhook retries by reason",
    labelnames=("reason",),
)


webhook_abort_total = _get_or_create_counter(
    "guardrail_webhook_abort_total",
    "Webhook aborts by reason",
    labelnames=("reason",),
)


webhook_dlq_retry_total = _get_or_create_counter(
    "guardrail_webhook_dlq_retry_total",
    "Manual requeue operations on the webhook DLQ",
)


webhook_dlq_purge_total = _get_or_create_counter(
    "guardrail_webhook_dlq_purge_total",
    "Manual purge operations on the webhook DLQ",
)


retention_preview_total = _get_or_create_counter(
    "guardrail_retention_preview_total",
    "Retention preview operations executed by admins",
)


retention_deleted_total = _get_or_create_counter(
    "guardrail_retention_deleted_total",
    "Retention deletes executed by admins",
    labelnames=("kind",),
)

secrets_strict_toggle_total = _get_or_create_counter(
    "guardrail_secrets_strict_toggle_total",
    "Admin toggled stricter secrets pack",
    labelnames=("action",),
)

admin_audit_total = _get_or_create_counter(
    "guardrail_admin_audit_total",
    "Admin action audit events",
    labelnames=("action", "outcome"),
)


def inc_ratelimit_script_reload() -> None:
    try:
        GUARDRAIL_RATELIMIT_REDIS_SCRIPT_RELOAD_TOTAL.inc()
    except Exception:
        pass


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
    ("tenant", "bot", "kind", "rule_id"),
)

GUARDRAIL_MITIGATION_OVERRIDE_TOTAL = _get_or_create_counter(
    "guardrail_mitigation_override_total",
    "Count of decisions where a tenant/bot mitigation override was applied.",
    ("mode",),
)

# Alias for newer code paths that expect an explicitly named counter.
mitigation_override_counter = GUARDRAIL_MITIGATION_OVERRIDE_TOTAL


def inc_clarify(phase: str = "ingress") -> None:
    GUARDRAIL_CLARIFY_TOTAL.labels(phase=phase).inc()


def inc_egress_redactions(
    tenant: str,
    bot: str,
    kind: str,
    n: int = 1,
    *,
    rule_id: str | None = None,
) -> None:
    if n > 0:
        tenant_l, bot_l = _limit_tenant_bot_labels(tenant, bot)
        try:
            GUARDRAIL_EGRESS_REDACTIONS_TOTAL.labels(
                tenant=tenant_l,
                bot=bot_l,
                kind=kind,
                rule_id=rule_id or "",
            ).inc(n)
        except Exception:
            pass


def inc_mitigation_override(mode: str) -> None:
    if mode in ("block", "clarify", "redact"):
        try:
            GUARDRAIL_MITIGATION_OVERRIDE_TOTAL.labels(mode=mode).inc()
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


# ---- Webhooks: DLQ length gauge ---------------------------------------------

_webhook_dlq_length = _get_or_create_gauge(
    "guardrail_webhook_dlq_length",
    "Number of webhook events currently queued in the DLQ.",
)


def webhook_dlq_length_set(n: float) -> None:
    try:
        _webhook_dlq_length.set(float(n))
    except Exception:
        # defensive: never throw from metrics path
        pass


def webhook_dlq_length_inc(delta: float = 1) -> None:
    try:
        _webhook_dlq_length.inc(float(delta))
    except Exception:
        pass


def webhook_dlq_length_dec(delta: float = 1) -> None:
    try:
        current = webhook_dlq_length_get()
        _webhook_dlq_length.set(max(0.0, current - float(delta)))
    except Exception:
        pass


def webhook_dlq_length_get() -> float:
    try:
        for metric in _webhook_dlq_length.collect():
            for sample in metric.samples:
                return float(sample.value)
    except Exception:
        pass
    return 0.0


# ---- Webhooks: delivery worker metrics --------------------------------------

_webhook_processed_total = _get_or_create_counter(
    "guardrail_webhook_deliveries_processed_total",
    "Count of webhook deliveries that succeeded with a 2xx response.",
)

_webhook_retried_total = _get_or_create_counter(
    "guardrail_webhook_deliveries_retried_total",
    "Count of webhook delivery attempts that will be retried.",
)

_webhook_failed_total = _get_or_create_counter(
    "guardrail_webhook_deliveries_failed_total",
    "Count of webhook deliveries that were dropped after exhausting retries.",
)

_webhook_pending_queue_length = _get_or_create_gauge(
    "guardrail_webhook_pending_queue_length",
    "Current number of webhook events waiting to be delivered.",
)


def webhook_processed_inc(n: float = 1) -> None:
    try:
        _webhook_processed_total.inc(float(n))
    except Exception:
        pass


def webhook_retried_inc(n: float = 1) -> None:
    try:
        _webhook_retried_total.inc(float(n))
    except Exception:
        pass


def webhook_failed_inc(n: float = 1) -> None:
    try:
        _webhook_failed_total.inc(float(n))
    except Exception:
        pass


def webhook_pending_set(n: float) -> None:
    try:
        _webhook_pending_queue_length.set(float(n))
    except Exception:
        pass

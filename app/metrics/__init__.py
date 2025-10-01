"""Prometheus metric helpers and common metric definitions."""
from __future__ import annotations

from typing import Iterable, Sequence

from prometheus_client import Counter, Gauge, Histogram

__all__ = [
    "metric_counter",
    "metric_gauge",
    "metric_histogram",
    "IDEMP_HITS",
    "IDEMP_MISSES",
    "IDEMP_REPLAYS",
    "IDEMP_CONFLICTS",
    "IDEMP_IN_PROGRESS",
    "IDEMP_EVICTIONS",
    "IDEMP_STREAMING_SKIPPED",
    "IDEMP_BODY_TOO_LARGE",
    "IDEMP_ERRORS",
    "IDEMP_LOCK_WAIT",
]


def _label_tuple(labels: Iterable[str] | None) -> Sequence[str]:
    return tuple(labels or ())


def metric_counter(name: str, documentation: str, labels: Iterable[str] | None = None) -> Counter:
    return Counter(name, documentation, _label_tuple(labels))


def metric_gauge(name: str, documentation: str, labels: Iterable[str] | None = None) -> Gauge:
    return Gauge(name, documentation, _label_tuple(labels))


def metric_histogram(name: str, documentation: str, labels: Iterable[str] | None = None) -> Histogram:
    return Histogram(name, documentation, _label_tuple(labels))


IDEMP_HITS = metric_counter("guardrail_idemp_hits_total", "Idempotency cache hits", ["method", "tenant"])
IDEMP_MISSES = metric_counter("guardrail_idemp_misses_total", "Idempotency cache misses", ["method", "tenant"])
IDEMP_REPLAYS = metric_counter(
    "guardrail_idemp_replays_total",
    "Responses served from idempotency store",
    ["method", "tenant"],
)
IDEMP_CONFLICTS = metric_counter(
    "guardrail_idemp_conflicts_total",
    "Same key but different payload fingerprint",
    ["method", "tenant"],
)
IDEMP_IN_PROGRESS = metric_gauge(
    "guardrail_idemp_in_progress_gauge",
    "Keys currently executing",
    ["tenant"],
)
IDEMP_EVICTIONS = metric_counter(
    "guardrail_idemp_evictions_total",
    "Store evictions/purges",
    ["tenant", "reason"],
)
IDEMP_STREAMING_SKIPPED = metric_counter(
    "guardrail_idemp_streaming_skipped_total",
    "Streaming responses not cached",
    ["method", "tenant"],
)
IDEMP_BODY_TOO_LARGE = metric_counter(
    "guardrail_idemp_body_too_large_total",
    "Bodies above cap (not cached)",
    ["tenant"],
)
IDEMP_ERRORS = metric_counter("guardrail_idemp_errors_total", "Errors by phase", ["phase"])
IDEMP_LOCK_WAIT = metric_histogram("guardrail_idemp_lock_wait_seconds", "Follower lock wait time")

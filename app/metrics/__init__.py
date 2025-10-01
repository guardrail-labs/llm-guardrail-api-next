"""Prometheus metric helpers and standard idempotency metrics."""

from __future__ import annotations

from typing import Iterable, Tuple

from prometheus_client import Counter, Gauge, Histogram


def _label_tuple(labels: Iterable[str] | None) -> Tuple[str, ...]:
    return tuple(labels) if labels else tuple()


def metric_counter(
    name: str,
    documentation: str,
    labels: Iterable[str] | None = None,
) -> Counter:
    return Counter(name, documentation, _label_tuple(labels))


def metric_gauge(
    name: str,
    documentation: str,
    labels: Iterable[str] | None = None,
) -> Gauge:
    return Gauge(name, documentation, _label_tuple(labels))


def metric_histogram(
    name: str,
    documentation: str,
    labels: Iterable[str] | None = None,
) -> Histogram:
    # Default buckets tuned for brief lock waits / middleware timings.
    return Histogram(
        name,
        documentation,
        _label_tuple(labels),
        buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
    )


# -------- Idempotency metrics (names stable) --------

IDEMP_HITS = metric_counter(
    "guardrail_idemp_hits_total",
    "Idempotency cache hits",
    ["method", "tenant"],
)
IDEMP_MISSES = metric_counter(
    "guardrail_idemp_misses_total",
    "Idempotency cache misses",
    ["method", "tenant"],
)
IDEMP_REPLAYS = metric_counter(
    "guardrail_idemp_replays_total",
    "Replays served from idempotency cache",
    ["method", "tenant"],
)
IDEMP_ERRORS = metric_counter(
    "guardrail_idemp_errors_total",
    "Errors raised inside idempotency layer",
    ["phase"],
)
IDEMP_IN_PROGRESS = metric_gauge(
    "guardrail_idemp_in_progress",
    "Number of leader requests currently in progress",
    ["tenant"],
)
IDEMP_LOCK_WAIT = metric_histogram(
    "guardrail_idemp_lock_wait_seconds",
    "Follower wait time for leader to finish or cache value",
)
IDEMP_CONFLICTS = metric_counter(
    "guardrail_idemp_conflicts_total",
    "Keys reused with different payload fingerprints",
    ["method", "tenant"],
)

# Additional counters referenced by observability and tests.
IDEMP_EVICTIONS = metric_counter(
    "guardrail_idemp_evictions_total",
    "Idempotency entries evicted or purged",
    ["reason"],
)
IDEMP_STREAMING_SKIPPED = metric_counter(
    "guardrail_idemp_streaming_skipped_total",
    "Streaming responses skipped from caching",
    ["method", "tenant"],
)
IDEMP_BODY_TOO_LARGE = metric_counter(
    "guardrail_idemp_body_toolarge_total",
    "Responses skipped from caching due to body size",
    ["method", "tenant"],
)

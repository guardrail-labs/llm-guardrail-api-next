"""Prometheus metric helpers and idempotency metrics."""
from __future__ import annotations

from typing import Iterable, Tuple

from prometheus_client import Counter, Gauge, Histogram


def _label_tuple(labels: Iterable[str] | None) -> Tuple[str, ...]:
    return tuple(labels) if labels else ()


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
    return Histogram(name, documentation, _label_tuple(labels))


# Core idempotency metrics (names kept stable)
IDEMP_HITS = metric_counter(
    "guardrail_idemp_hits_total",
    "Idempotency cache hits",
    ["method", "tenant", "role"],
)
IDEMP_MISSES = metric_counter(
    "guardrail_idemp_misses_total",
    "Idempotency cache misses",
    ["method", "tenant", "role"],
)
IDEMP_REPLAYS = metric_counter(
    "guardrail_idemp_replays_total",
    "Responses served from idempotency cache",
    ["method", "tenant", "role"],
)
IDEMP_LOCK_WAIT = metric_histogram(
    "guardrail_idemp_lock_wait_seconds",
    "Follower wait time while leader in-progress",
)
IDEMP_IN_PROGRESS = metric_counter(
    "guardrail_idemp_in_progress_total",
    "Leader executions in progress",
    ["tenant", "role"],
)
IDEMP_CONFLICTS = metric_counter(
    "guardrail_idemp_conflicts_total",
    "Conflicting payload fingerprint seen for same key",
    ["method", "tenant", "role"],
)
IDEMP_ERRORS = metric_counter(
    "guardrail_idemp_errors_total",
    "Errors during idempotency phases",
    ["phase"],
)

IDEMP_TOUCHES = metric_counter(
    "guardrail_idemp_touches_total",
    "Idempotency TTL refreshes (touch) on replay",
    ["tenant"],
)

IDEMP_RECENT_SIZE = metric_gauge(
    "guardrail_idemp_recent_size",
    "Current size of idempotency recent ring",
    ["tenant"],
)

IDEMP_PURGES = metric_counter(
    "guardrail_idemp_purges_total",
    "Admin-triggered idempotency purges",
    ["tenant"],
)

IDEMP_STUCK_LOCKS = metric_counter(
    "guardrail_idemp_stuck_locks_total",
    "Locks purged after exceeding TTL",
    ["tenant"],
)

IDEMP_REPLAY_COUNT_HIST = metric_histogram(
    "guardrail_idemp_replay_count",
    "Observed replay_count values on replay",
    ["tenant", "method"],
)

# Additional observability used by tests and dashboards
IDEMP_STREAMING_SKIPPED = metric_counter(
    "guardrail_idemp_streaming_skipped_total",
    "Streaming responses were not cached",
)
IDEMP_BODY_TOO_LARGE = metric_counter(
    "guardrail_idemp_body_too_large_total",
    "Responses too large to cache",
)
IDEMP_EVICTIONS = metric_counter(
    "guardrail_idemp_evictions_total",
    "Explicit evictions from idempotency store",
)


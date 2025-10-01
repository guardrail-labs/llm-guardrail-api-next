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


# --- Idempotency metrics -----------------------------------------------------

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
    "Idempotency replays served",
    ["method", "tenant"],
)

IDEMP_ERRORS = metric_counter(
    "guardrail_idemp_errors_total",
    "Errors in idempotency layer",
    ["phase"],
)

IDEMP_CONFLICTS = metric_counter(
    "guardrail_idemp_conflicts_total",
    "Conflicting payload fingerprints while in-flight",
    ["method", "tenant"],
)

IDEMP_IN_PROGRESS = metric_counter(
    "guardrail_idemp_in_progress_total",
    "Leader executions started",
    ["tenant"],
)

IDEMP_LOCK_WAIT = metric_histogram(
    "guardrail_idemp_lock_wait_seconds",
    "Follower time spent waiting for leader to finish",
)

IDEMP_BACKOFF_STEPS = metric_counter(
    "guardrail_idemp_backoff_steps_total",
    "Backoff steps taken by followers",
)

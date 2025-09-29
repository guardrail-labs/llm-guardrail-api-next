"""Prometheus metrics for idempotency middleware."""

from prometheus_client import Counter, Gauge, Histogram

IDEMP_HITS = Counter(
    "guardrail_idemp_hits_total",
    "Idempotency cache hits",
    ["method", "tenant"],
)
IDEMP_MISSES = Counter(
    "guardrail_idemp_misses_total",
    "Idempotency cache misses",
    ["method", "tenant"],
)
IDEMP_REPLAYS = Counter(
    "guardrail_idemp_replays_total",
    "Responses served from idempotency store",
    ["method", "tenant"],
)
IDEMP_CONFLICTS = Counter(
    "guardrail_idemp_conflicts_total",
    "Same key but different fingerprint",
    ["method", "tenant"],
)
IDEMP_IN_PROGRESS = Gauge(
    "guardrail_idemp_in_progress_gauge",
    "Number of keys executing",
    ["tenant"],
)
IDEMP_EVICTIONS = Counter(
    "guardrail_idemp_evictions_total",
    "Store evictions or purges",
    ["tenant", "reason"],
)
IDEMP_STREAMING_SKIPPED = Counter(
    "guardrail_idemp_streaming_skipped_total",
    "Streaming responses not cached",
    ["method", "tenant"],
)
IDEMP_BODY_TOO_LARGE = Counter(
    "guardrail_idemp_body_too_large_total",
    "Bodies above cap (not cached)",
    ["tenant"],
)
IDEMP_ERRORS = Counter(
    "guardrail_idemp_errors_total",
    "Errors by phase",
    ["phase"],
)
IDEMP_LOCK_WAIT = Histogram(
    "guardrail_idemp_lock_wait_seconds",
    "Follower lock wait time",
)

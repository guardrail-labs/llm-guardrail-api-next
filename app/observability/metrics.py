from __future__ import annotations

from dataclasses import dataclass

from prometheus_client import REGISTRY, CollectorRegistry, Counter, Histogram


@dataclass(frozen=True)
class VerifierMetrics:
    sampled_total: Counter
    skipped_total: Counter
    timeout_total: Counter
    duration_seconds: Histogram  # labeled by provider


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
    return VerifierMetrics(
        sampled_total=sampled,
        skipped_total=skipped,
        timeout_total=timeout,
        duration_seconds=duration,
    )


# Default metrics used by the app
VERIFIER_METRICS: VerifierMetrics = make_verifier_metrics(REGISTRY)

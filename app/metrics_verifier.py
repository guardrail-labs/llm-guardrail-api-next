from __future__ import annotations

from prometheus_client import Counter

verifier_events = Counter(
    "guardrail_verifier_events_total",
    "Verifier events",
    labelnames=("provider", "event"),
)

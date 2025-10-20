from __future__ import annotations

from prometheus_client import Counter

sanitizer_events = Counter(
    "guardrail_sanitizer_events_total",
    "Sanitizer events (unicode/confusables/etc.)",
    labelnames=("tenant", "type"),
)

sanitizer_actions = Counter(
    "guardrail_sanitizer_actions_total",
    "Sanitizer actions taken per policy",
    labelnames=("tenant", "action"),
)

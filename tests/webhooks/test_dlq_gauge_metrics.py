from __future__ import annotations

from app.observability import metrics


def test_webhook_dlq_gauge_inc_dec_roundtrip() -> None:
    base = metrics.webhook_dlq_length_get()
    metrics.webhook_dlq_length_set(0)
    assert metrics.webhook_dlq_length_get() == 0.0

    metrics.webhook_dlq_length_inc()
    metrics.webhook_dlq_length_inc(2)
    assert metrics.webhook_dlq_length_get() == 3.0

    metrics.webhook_dlq_length_dec()
    assert metrics.webhook_dlq_length_get() == 2.0

    metrics.webhook_dlq_length_set(7)
    assert metrics.webhook_dlq_length_get() == 7.0

    metrics.webhook_dlq_length_dec(10)
    assert metrics.webhook_dlq_length_get() >= 0.0

    metrics.webhook_dlq_length_set(base)

from __future__ import annotations

import pytest

import app.services.webhooks as wh
from app.observability import metrics


def test_dlq_gauge_seeded_on_configure_without_reset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = metrics.webhook_dlq_length_get()
    metrics.webhook_dlq_length_set(0)

    monkeypatch.setattr(wh, "dlq_count", lambda: 3)

    try:
        wh.configure(reset=False)
        assert metrics.webhook_dlq_length_get() == 3.0
    finally:
        metrics.webhook_dlq_length_set(base)

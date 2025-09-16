from __future__ import annotations

import pytest

import app.services.webhooks as wh
from app.observability import metrics


def test_dlq_write_increments_gauge(tmp_path, monkeypatch) -> None:
    if not hasattr(wh, "_dlq_write"):
        pytest.skip("_dlq_write helper unavailable")

    base = metrics.webhook_dlq_length_get()
    metrics.webhook_dlq_length_set(0)

    monkeypatch.setattr(wh, "_DLQ_PATH", str(tmp_path / "dlq.jsonl"))

    wh._dlq_write({"id": "t1"}, reason="test")

    assert metrics.webhook_dlq_length_get() == 1.0

    metrics.webhook_dlq_length_set(base)

from __future__ import annotations

import json
import time
from typing import Dict

import pytest
from prometheus_client import generate_latest

from app.services import webhooks
from app.services.config_store import reset_config
from app.telemetry import metrics as m


def _wait_for_processed(expected: int, timeout: float = 2.0) -> Dict[str, int]:
    deadline = time.time() + timeout
    last = webhooks.stats()
    while time.time() < deadline:
        last = webhooks.stats()
        if last.get("processed", 0) >= expected:
            return last
        time.sleep(0.01)
    raise AssertionError(f"Timed out waiting for processed>={expected}: {last}")


def _metric_totals() -> Dict[str, float]:
    text = generate_latest(m.PROM_REGISTRY).decode("utf-8")
    totals: Dict[str, float] = {}
    prefix = "GUARDRAIL_WEBHOOK_EVENTS_TOTAL_total{"
    for line in text.splitlines():
        if not line.startswith(prefix):
            continue
        head, value = line.split(" ", 1)
        label_chunk = head[len(prefix) : head.rfind("}")]
        labels: Dict[str, str] = {}
        if label_chunk:
            for part in label_chunk.split(","):
                key, raw_val = part.split("=", 1)
                labels[key] = raw_val.strip('"')
        outcome = labels.get("outcome")
        if outcome:
            totals[outcome] = float(value)
    return totals


def test_enqueue_disabled_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    reset_config()
    webhooks.configure(reset=True)
    monkeypatch.delenv("WEBHOOK_ENABLE", raising=False)

    start_totals = _metric_totals()

    payload = {"request_id": "disabled", "status": 200}
    webhooks.enqueue(payload)

    stats = _wait_for_processed(1)
    assert stats["queued"] == 1
    assert stats["processed"] == 1
    assert stats["dropped"] == 0

    end_totals = _metric_totals()
    assert end_totals.get("enqueued", 0.0) >= start_totals.get("enqueued", 0.0) + 1
    assert end_totals.get("processed", 0.0) >= start_totals.get("processed", 0.0) + 1
    assert end_totals.get("dropped", 0.0) == start_totals.get("dropped", 0.0)

    webhooks.configure(reset=True)


def test_enqueue_with_file(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    reset_config()
    events_file = tmp_path / "events.jsonl"
    webhooks.configure(path=str(events_file), reset=True)
    monkeypatch.setenv("WEBHOOK_ENABLE", "true")

    start_totals = _metric_totals()

    payload = {"request_id": "enabled", "status": 201}
    webhooks.enqueue(payload)

    stats = _wait_for_processed(1)
    assert stats["queued"] == 1
    assert stats["processed"] == 1
    assert stats["dropped"] == 0

    content = events_file.read_text(encoding="utf-8").splitlines()
    assert len(content) == 1
    assert json.loads(content[0]) == payload

    end_totals = _metric_totals()
    assert end_totals.get("enqueued", 0.0) >= start_totals.get("enqueued", 0.0) + 1
    assert end_totals.get("processed", 0.0) >= start_totals.get("processed", 0.0) + 1

    webhooks.configure(reset=True)

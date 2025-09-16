from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, Mapping, Tuple

import httpx
import pytest
from prometheus_client import generate_latest

from app.services import webhooks
from app.services.config_store import get_config, reset_config, set_config
from app.telemetry import metrics as m

LabelKey = Tuple[Tuple[str, str], ...]


def _wait_for_processed(expected: int, timeout: float = 2.0) -> Dict[str, Any]:
    deadline = time.time() + timeout
    last = webhooks.stats()
    while time.time() < deadline:
        last = webhooks.stats()
        if last.get("processed", 0) >= expected:
            return last
        time.sleep(0.01)
    raise AssertionError(f"Timed out waiting for processed>={expected}: {last}")


def _counter_totals(name: str) -> Dict[LabelKey, float]:
    text = generate_latest(m.PROM_REGISTRY).decode("utf-8")
    prefix = f"{name}{{"
    totals: Dict[LabelKey, float] = {}
    for line in text.splitlines():
        if not line.startswith(prefix):
            continue
        head, value = line.split(" ", 1)
        labels_raw = head[len(prefix) : head.rfind("}")]
        labels: list[tuple[str, str]] = []
        if labels_raw:
            for part in labels_raw.split(","):
                key, raw_val = part.split("=", 1)
                labels.append((key, raw_val.strip('"')))
        totals[tuple(sorted(labels))] = float(value)
    return totals


def _labels(key_values: Mapping[str, str]) -> LabelKey:
    return tuple(sorted(key_values.items()))


def _value_for(labels: Mapping[str, str], counters: Dict[LabelKey, float]) -> float:
    return counters.get(_labels(labels), 0.0)


def test_enqueue_without_url_records_failure() -> None:
    initial_cfg = dict(get_config())
    try:
        set_config(
            {
                "webhook_enable": False,
                "webhook_url": "",
                "webhook_secret": "",
                "webhook_allow_insecure_tls": False,
                "webhook_allowlist_host": "",
            },
            replace=True,
        )
        webhooks.configure(reset=True)

        start_events = _counter_totals("guardrail_webhook_events_total")
        start_deliveries = _counter_totals("guardrail_webhook_deliveries_total")

        payload = {"request_id": "disabled", "status": 200}
        webhooks.enqueue(payload)

        stats = _wait_for_processed(1)
        assert stats["queued"] == 1
        assert stats["processed"] >= 1
        assert stats["last_status"] == "error"
        assert stats["last_error"] == "error"

        end_events = _counter_totals("guardrail_webhook_events_total")
        end_deliveries = _counter_totals("guardrail_webhook_deliveries_total")

        assert (
            _value_for({"outcome": "enqueued"}, end_events)
            >= _value_for({"outcome": "enqueued"}, start_events) + 1
        )
        assert (
            _value_for({"outcome": "failed", "status": "error"}, end_deliveries)
            >= _value_for({"outcome": "failed", "status": "error"}, start_deliveries) + 1
        )

    finally:
        set_config(initial_cfg, replace=True)
        reset_config()
        webhooks.configure(reset=True)


def test_failed_delivery_writes_dlq(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    initial_cfg = dict(get_config())
    try:
        set_config(
            {
                "webhook_enable": True,
                "webhook_url": "https://example.com/hook",
                "webhook_timeout_ms": 50,
                "webhook_max_retries": 0,
                "webhook_backoff_ms": 1,
                "webhook_allow_insecure_tls": True,
                "webhook_allowlist_host": "example.com",
            },
            replace=True,
        )
        webhooks.configure(reset=True)

        dlq_path = tmp_path / "webhook_dlq.jsonl"
        monkeypatch.setattr(webhooks, "_DLQ_PATH", str(dlq_path), raising=False)

        start_deliveries = _counter_totals("guardrail_webhook_deliveries_total")

        def fake_post(
            self: httpx.Client,
            url: str,
            content: bytes | None = None,
            headers: Mapping[str, str] | None = None,
        ) -> httpx.Response:
            return httpx.Response(status_code=500)

        monkeypatch.setattr(httpx.Client, "post", fake_post, raising=True)

        webhooks.enqueue({"incident_id": "dlq", "request_id": "dlq", "status": 500})

        stats = _wait_for_processed(1)
        assert stats["processed"] >= 1
        assert stats["last_status"] == "5xx"
        assert stats["last_error"] == "5xx"

        assert dlq_path.exists()
        contents = dlq_path.read_text(encoding="utf-8").strip().splitlines()
        assert contents
        record = json.loads(contents[-1])
        assert record["reason"] == "5xx"
        assert record["event"]["incident_id"] == "dlq"

        deliveries = _counter_totals("guardrail_webhook_deliveries_total")
        assert (
            _value_for({"outcome": "dlq", "status": "5xx"}, deliveries)
            >= _value_for({"outcome": "dlq", "status": "5xx"}, start_deliveries) + 1
        )

    finally:
        set_config(initial_cfg, replace=True)
        reset_config()
        webhooks.configure(reset=True)

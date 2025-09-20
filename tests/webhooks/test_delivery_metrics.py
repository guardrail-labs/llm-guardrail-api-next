from __future__ import annotations

import time
from typing import Dict, Iterator

import httpx
import pytest
from prometheus_client import REGISTRY, generate_latest
from starlette.testclient import TestClient

from app.main import create_app
from app.services.config_store import reset_config, set_config
from app.services.webhooks import configure, enqueue


class _MockResp:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


def _metrics_snapshot() -> Dict[str, float]:
    text = generate_latest(REGISTRY).decode()
    values: Dict[str, float] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if "{" in line:
            continue
        parts = line.split()
        if len(parts) != 2:
            continue
        name, raw = parts
        try:
            values[name] = float(raw)
        except ValueError:
            continue
    return values


def _wait_for_metric(name: str, target: float, timeout: float = 5.0) -> float:
    deadline = time.time() + timeout
    last = 0.0
    while time.time() < deadline:
        metrics = _metrics_snapshot()
        last = metrics.get(name, 0.0)
        if last >= target:
            return last
        time.sleep(0.05)
    return last


def _wait_for_gauge(name: str, expected: float, timeout: float = 5.0) -> float:
    deadline = time.time() + timeout
    last = 0.0
    while time.time() < deadline:
        metrics = _metrics_snapshot()
        last = metrics.get(name, 0.0)
        if abs(last - expected) < 1e-6:
            return last
        time.sleep(0.05)
    return last


def _configure_webhooks() -> None:
    set_config(
        {
            "webhook_enable": True,
            "webhook_url": "https://example.com/hook",
            "webhook_secret": "s3cr3t",
            "webhook_timeout_ms": 50,
            "webhook_max_retries": 2,
            "webhook_backoff_ms": 1,
            "webhook_allow_insecure_tls": True,
            "webhook_allowlist_host": "example.com",
        }
    )
    configure(reset=True)


@pytest.fixture(autouse=True)
def _cleanup_config() -> Iterator[None]:
    try:
        yield
    finally:
        reset_config()


def test_webhook_metrics_processed_and_pending(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_webhooks()

    monkeypatch.setattr(
        httpx.Client,
        "post",
        lambda self, url, content=None, headers=None: _MockResp(200),
        raising=True,
    )

    before = _metrics_snapshot()

    enqueue({"incident_id": "p1", "request_id": "p1", "ts": 1})

    app = create_app()
    with TestClient(app) as client:
        client.get("/metrics")

    processed = _wait_for_metric(
        "guardrail_webhook_deliveries_processed_total",
        before.get("guardrail_webhook_deliveries_processed_total", 0.0) + 1.0,
    )
    assert processed == pytest.approx(
        before.get("guardrail_webhook_deliveries_processed_total", 0.0) + 1.0
    )

    pending = _wait_for_gauge("guardrail_webhook_pending_queue_length", 0.0)
    assert pending == pytest.approx(0.0)


def test_webhook_metrics_retry_increments(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_webhooks()

    calls = {"n": 0}

    def fake_post(
        self: httpx.Client,
        url: str,
        content: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> _MockResp:
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.TimeoutException("timeout")
        return _MockResp(200)

    monkeypatch.setattr(httpx.Client, "post", fake_post, raising=True)

    before = _metrics_snapshot()

    enqueue({"incident_id": "r1", "request_id": "r1", "ts": 1})

    app = create_app()
    with TestClient(app) as client:
        client.get("/metrics")

    processed = _wait_for_metric(
        "guardrail_webhook_deliveries_processed_total",
        before.get("guardrail_webhook_deliveries_processed_total", 0.0) + 1.0,
    )
    assert processed >= before.get("guardrail_webhook_deliveries_processed_total", 0.0) + 1.0

    retried = _wait_for_metric(
        "guardrail_webhook_deliveries_retried_total",
        before.get("guardrail_webhook_deliveries_retried_total", 0.0) + 1.0,
    )
    assert retried >= before.get("guardrail_webhook_deliveries_retried_total", 0.0) + 1.0


def test_webhook_metrics_failure_increments(monkeypatch: pytest.MonkeyPatch) -> None:
    set_config(
        {
            "webhook_enable": True,
            "webhook_url": "https://example.com/hook",
            "webhook_secret": "s3cr3t",
            "webhook_timeout_ms": 50,
            "webhook_max_retries": 1,
            "webhook_backoff_ms": 1,
            "webhook_allow_insecure_tls": True,
            "webhook_allowlist_host": "example.com",
        }
    )
    configure(reset=True)

    monkeypatch.setattr(
        httpx.Client,
        "post",
        lambda self, url, content=None, headers=None: _MockResp(500),
        raising=True,
    )

    before = _metrics_snapshot()

    enqueue({"incident_id": "f1", "request_id": "f1", "ts": 1})

    app = create_app()
    with TestClient(app) as client:
        client.get("/metrics")

    failed = _wait_for_metric(
        "guardrail_webhook_deliveries_failed_total",
        before.get("guardrail_webhook_deliveries_failed_total", 0.0) + 1.0,
        timeout=10.0,
    )
    assert failed >= before.get("guardrail_webhook_deliveries_failed_total", 0.0) + 1.0

    pending = _wait_for_gauge("guardrail_webhook_pending_queue_length", 0.0)
    assert pending == pytest.approx(0.0)

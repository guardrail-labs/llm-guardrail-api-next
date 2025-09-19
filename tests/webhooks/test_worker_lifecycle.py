from __future__ import annotations

import time
from typing import Any, Dict

import httpx
from starlette.testclient import TestClient

from app.main import create_app
from app.services import webhooks
from app.services.config_store import reset_config, set_config


class _MockResp:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


def _wait_for_processed(min_count: int, timeout: float = 2.0) -> Dict[str, Any]:
    deadline = time.time() + timeout
    last = webhooks.stats()
    while time.time() < deadline:
        last = webhooks.stats()
        if last.get("processed", 0) >= min_count:
            return last
        time.sleep(0.01)
    raise AssertionError(f"Timed out waiting for processed>={min_count}: {last}")


def test_worker_starts_and_stops(monkeypatch) -> None:
    set_config(
        {
            "webhook_enable": True,
            "webhook_url": "https://example.com/hook",
            "webhook_secret": "s3cr3t",
            "webhook_timeout_ms": 50,
            "webhook_max_retries": 0,
            "webhook_backoff_ms": 1,
            "webhook_allow_insecure_tls": True,
            "webhook_allowlist_host": "example.com",
        }
    )
    webhooks.configure(reset=True)

    def fake_post(
        self: httpx.Client,
        url: str,
        content: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> _MockResp:
        return _MockResp(200)

    monkeypatch.setattr(httpx.Client, "post", fake_post, raising=True)

    starts: dict[str, int] = {"n": 0}
    stops: dict[str, int] = {"n": 0}
    orig_start = webhooks.ensure_started
    orig_shutdown = webhooks.shutdown

    def tracked_start() -> None:
        starts["n"] += 1
        orig_start()

    def tracked_shutdown() -> None:
        stops["n"] += 1
        orig_shutdown()

    monkeypatch.setattr(webhooks, "ensure_started", tracked_start)
    monkeypatch.setattr(webhooks, "shutdown", tracked_shutdown)

    webhooks.enqueue({"incident_id": "life", "request_id": "life", "status": 200})

    with TestClient(create_app()) as client:
        client.get("/metrics")
        _wait_for_processed(1)

    assert starts["n"] >= 1
    assert stops["n"] >= 1

    reset_config()
    webhooks.configure(reset=True)

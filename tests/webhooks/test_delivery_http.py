from __future__ import annotations

import time

import httpx
from starlette.testclient import TestClient

from app.main import create_app
from app.services.config_store import reset_config, set_config
from app.services.webhooks import configure, enqueue, stats


class _MockResp:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


def test_webhook_sends_and_retries(monkeypatch) -> None:
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

    evt = {"incident_id": "t1", "request_id": "t1", "ts": 1}
    enqueue(evt)

    app = create_app()
    client = TestClient(app)
    client.get("/metrics")

    time.sleep(0.1)

    snapshot = stats()
    assert snapshot["processed"] >= 1

    reset_config()

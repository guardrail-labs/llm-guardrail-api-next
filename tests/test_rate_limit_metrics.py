from __future__ import annotations

import importlib

from fastapi.testclient import TestClient


class _CounterStub:
    def __init__(self) -> None:
        self.labels_args: list[dict[str, str]] = []
        self.count = 0

    def labels(self, **labels):
        self.labels_args.append(labels)
        return self

    def inc(self) -> None:
        self.count += 1


def _client_and_counter(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_RPS", "1")
    monkeypatch.setenv("RATE_LIMIT_BURST", "1")
    monkeypatch.setenv("API_KEY", "test-key")

    import app.services.ratelimit as rl

    importlib.reload(rl)
    counter = _CounterStub()
    monkeypatch.setattr(rl, "RATE_LIMIT_BLOCKS", counter)
    monkeypatch.setattr(rl, "_global_enabled", None, raising=False)
    monkeypatch.setattr(rl, "_global_limiter", None, raising=False)

    import app.middleware.rate_limit as middleware

    importlib.reload(middleware)
    monkeypatch.setattr(middleware, "RATE_LIMIT_BLOCKS", counter)

    import app.main as main

    importlib.reload(main)
    return TestClient(main.app), counter


def test_metric_increment_called(monkeypatch):
    client, counter = _client_and_counter(monkeypatch)
    headers = {
        "X-Guardrail-Tenant": "acme",
        "X-Guardrail-Bot": "web",
        "X-API-Key": "test-key",
    }

    assert client.post("/guardrail/", json={"prompt": "ok"}, headers=headers).status_code in (
        200,
        202,
        207,
    )
    blocked = client.post("/guardrail/", json={"prompt": "again"}, headers=headers)
    assert blocked.status_code == 429
    assert counter.count == 1
    assert counter.labels_args == [{"tenant": "acme", "bot": "web"}]

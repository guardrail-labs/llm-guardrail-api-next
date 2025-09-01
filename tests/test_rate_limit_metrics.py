from __future__ import annotations

import importlib
import logging
from typing import Callable

from fastapi.testclient import TestClient


def _client_with(monkeypatch, inc_fn: Callable[[float], None]) -> TestClient:
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_PER_MINUTE", "1")
    monkeypatch.setenv("RATE_LIMIT_BURST", "1")
    monkeypatch.setenv("API_KEY", "test")

    import app.telemetry.metrics as metrics
    importlib.reload(metrics)
    import app.middleware.rate_limit as rl
    importlib.reload(rl)
    monkeypatch.setattr(rl, "inc_rate_limited", inc_fn)
    import app.main as main
    importlib.reload(main)
    return TestClient(main.app)


def test_metric_increment_called(monkeypatch):
    calls = {"n": 0}

    def fake_inc(by: float = 1.0) -> None:
        calls["n"] += 1

    client = _client_with(monkeypatch, fake_inc)
    h = {"X-API-Key": "test"}
    assert client.post("/guardrail/", json={"prompt": "ok"}, headers=h).status_code == 200
    r2 = client.post("/guardrail/", json={"prompt": "again"}, headers=h)
    assert r2.status_code == 429
    assert calls["n"] == 1


def test_metric_increment_exception(monkeypatch, caplog):
    def bad_inc(by: float = 1.0) -> None:
        raise RuntimeError("boom")

    client = _client_with(monkeypatch, bad_inc)
    h = {"X-API-Key": "test"}
    assert client.post("/guardrail/", json={"prompt": "ok"}, headers=h).status_code == 200

    with caplog.at_level(logging.WARNING):
        r2 = client.post("/guardrail/", json={"prompt": "again"}, headers=h)
    assert r2.status_code == 429
    assert "inc_rate_limited failed" in caplog.text

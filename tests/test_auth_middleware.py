from __future__ import annotations

import importlib

from fastapi.testclient import TestClient


def _client(monkeypatch) -> TestClient:
    monkeypatch.setenv("GUARDRAIL_DISABLE_AUTH", "0")

    import app.telemetry.metrics as metrics
    importlib.reload(metrics)
    import app.main as main
    importlib.reload(main)

    return TestClient(main.app)


def test_auth_blocks_without_key(monkeypatch):
    c = _client(monkeypatch)
    # Protected route (proxy) should 401 without auth
    r = c.post("/proxy/chat", json={"model": "demo", "messages": []})
    assert r.status_code == 401
    j = r.json()
    assert j["detail"] == "Unauthorized"
    assert "request_id" in j


def test_health_and_metrics_open(monkeypatch):
    c = _client(monkeypatch)
    assert c.get("/health").status_code == 200
    assert c.get("/metrics").status_code == 200


def test_auth_allows_with_key(monkeypatch):
    c = _client(monkeypatch)
    r = c.post(
        "/proxy/chat",
        json={"model": "demo", "messages": [{"role": "user", "content": "hi"}]},
        headers={"X-API-Key": "k", "Content-Type": "application/json"},
    )
    assert r.status_code == 200


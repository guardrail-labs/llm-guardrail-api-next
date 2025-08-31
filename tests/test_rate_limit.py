from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app


def test_rate_limit_burst_then_429(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_PER_MINUTE", "60")
    monkeypatch.setenv("RATE_LIMIT_BURST", "60")

    client = TestClient(create_app())

    last = None
    headers = {"X-API-Key": "test"}
    for i in range(61):
        r = client.post("/guardrail/", json={"prompt": f"ping {i}"}, headers=headers)
        last = r.status_code
    assert last == 429

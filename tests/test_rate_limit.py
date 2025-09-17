from __future__ import annotations

import importlib

from fastapi.testclient import TestClient


def _fresh_app(monkeypatch):
    monkeypatch.setenv("API_KEY", "test-key")
    import app.services.ratelimit as rl

    importlib.reload(rl)
    monkeypatch.setattr(rl, "_global_enabled", None, raising=False)
    monkeypatch.setattr(rl, "_global_limiter", None, raising=False)

    import app.middleware.rate_limit as middleware

    importlib.reload(middleware)

    import app.main as main

    importlib.reload(main)
    return main.app


def test_rate_limit_burst_then_429(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_RPS", "5")
    monkeypatch.setenv("RATE_LIMIT_BURST", "5")

    app = _fresh_app(monkeypatch)
    client = TestClient(app)

    headers = {
        "X-Guardrail-Tenant": "acme",
        "X-Guardrail-Bot": "bot",
        "X-API-Key": "test-key",
    }
    for _ in range(5):
        resp = client.post("/guardrail/", json={"prompt": "ping"}, headers=headers)
        assert resp.status_code in (200, 202, 207, 429)
        if resp.status_code == 429:
            break
    blocked = client.post("/guardrail/", json={"prompt": "again"}, headers=headers)
    assert blocked.status_code == 429
    assert blocked.headers.get("Retry-After")

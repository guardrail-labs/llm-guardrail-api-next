from __future__ import annotations

import importlib

from fastapi.testclient import TestClient


def _reload_app(monkeypatch):
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


def test_ratelimit_sanitizes_identities(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_RPS", "1")
    monkeypatch.setenv("RATE_LIMIT_BURST", "1")

    app = _reload_app(monkeypatch)
    client = TestClient(app)

    headers = {
        "X-Guardrail-Tenant": "acme$%^",
        "X-Guardrail-Bot": "web/1",
        "X-API-Key": "test-key",
    }

    assert client.post("/guardrail/", json={"prompt": "ok"}, headers=headers).status_code in (
        200,
        202,
        207,
    )
    blocked = client.post("/guardrail/", json={"prompt": "again"}, headers=headers)
    assert blocked.status_code == 429
    body = blocked.json()
    assert body["tenant"] == "acme_"
    assert body["bot"] == "web_1"

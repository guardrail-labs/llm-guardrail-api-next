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


def test_ratelimit_headers_and_429(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_RPS", "1")
    monkeypatch.setenv("RATE_LIMIT_BURST", "1")

    app = _reload_app(monkeypatch)
    client = TestClient(app)

    headers = {
        "X-Guardrail-Tenant": "acme",
        "X-Guardrail-Bot": "web",
        "X-API-Key": "test-key",
    }

    allowed = client.post("/guardrail/", json={"prompt": "ping"}, headers=headers)
    assert allowed.status_code in (200, 202, 207)
    assert allowed.headers.get("X-RateLimit-Limit") == "1; burst=1"
    assert allowed.headers.get("X-RateLimit-Remaining") == "0"
    assert allowed.headers.get("X-Quota-Remaining") == "0"
    assert allowed.headers.get("X-Quota-Reset") is not None

    blocked = client.post("/guardrail/", json={"prompt": "again"}, headers=headers)
    assert blocked.status_code == 429
    assert blocked.headers.get("Retry-After") == "1"
    assert blocked.headers.get("X-RateLimit-Limit") == "1; burst=1"
    assert blocked.headers.get("X-RateLimit-Remaining") == "0"
    assert blocked.headers.get("X-Quota-Remaining") == "0"
    assert blocked.headers.get("X-Quota-Reset") == "1"

    payload = blocked.json()
    assert payload["detail"] == "Rate limit exceeded"
    assert payload["tenant"] == "acme"
    assert payload["bot"] == "web"
    assert payload["retry_after_seconds"] == 1

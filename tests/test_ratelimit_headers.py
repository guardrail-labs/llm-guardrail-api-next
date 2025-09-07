from __future__ import annotations

import importlib

from fastapi.testclient import TestClient


def _reload_app():
    # Ensure a fresh app with env-applied state
    import app.telemetry.metrics as metrics

    importlib.reload(metrics)
    import app.main as main

    importlib.reload(main)
    return main.app


def test_ratelimit_headers_and_429(monkeypatch):
    # Enable rate limiting with tiny burst so we can hit 429 quickly
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_PER_MINUTE", "2")
    monkeypatch.setenv("RATE_LIMIT_BURST", "2")

    app = _reload_app()
    client = TestClient(app)

    # First two should pass and include headers
    r1 = client.get("/health")
    assert r1.status_code == 200
    assert "X-RateLimit-Limit" in r1.headers
    assert "X-RateLimit-Remaining" in r1.headers
    assert "X-RateLimit-Reset" in r1.headers

    r2 = client.get("/health")
    assert r2.status_code == 200
    assert r2.headers.get("X-RateLimit-Limit") == "2"
    # Remaining should be <= 1 after second request
    assert int(r2.headers.get("X-RateLimit-Remaining", "0")) <= 1

    # Third should be blocked
    r3 = client.get("/health")
    assert r3.status_code == 429
    assert r3.headers.get("Retry-After") == "60"
    assert r3.headers.get("X-RateLimit-Limit") == "2"
    assert r3.headers.get("X-RateLimit-Remaining") == "0"
    assert "X-RateLimit-Reset" in r3.headers

    # Body shape for consistency with other 429s
    j = r3.json()
    assert j["code"] == "rate_limited"
    assert "request_id" in j

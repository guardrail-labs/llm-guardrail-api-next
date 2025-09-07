import importlib
import os

from fastapi.testclient import TestClient


def _make_client():
    os.environ["API_KEY"] = "unit-test-key"

    import app.config as cfg

    importlib.reload(cfg)
    import app.main as main

    importlib.reload(main)

    return TestClient(main.build_app())


def test_cors_allows_origin_header_on_simple_get():
    os.environ["CORS_ALLOW_ORIGINS"] = "http://example.com"
    client = _make_client()

    r = client.get("/health", headers={"Origin": "http://example.com"})
    assert r.status_code == 200
    # CORS middleware echoes the origin when specifically allowed
    assert r.headers.get("access-control-allow-origin") == "http://example.com"


def test_rate_limit_429_after_burst(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_PER_MINUTE", "2")
    monkeypatch.setenv("RATE_LIMIT_BURST", "2")

    client = _make_client()

    h = {"X-API-Key": "unit-test-key"}
    # First two allowed
    assert client.post("/guardrail/", json={"prompt": "ok"}, headers=h).status_code == 200
    assert client.post("/guardrail/", json={"prompt": "ok2"}, headers=h).status_code == 200
    # Third should be limited
    r3 = client.post("/guardrail/", json={"prompt": "ok3"}, headers=h)
    assert r3.status_code == 429
    assert "rate limit exceeded" in r3.json().get("detail", "").lower()

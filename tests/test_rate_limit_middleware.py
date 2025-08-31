from __future__ import annotations

import importlib
import time

from fastapi.testclient import TestClient


def _client():
    # Rebuild app with current env
    import app.main as main
    importlib.reload(main)
    return TestClient(main.app)


def test_headers_present_when_disabled(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_PER_MINUTE", "2")
    monkeypatch.setenv("RATE_LIMIT_BURST", "2")

    c = _client()
    r = c.get("/health", headers={"X-Tenant-ID": "acme", "X-Bot-ID": "bot-a"})
    assert r.status_code == 200
    assert "X-RateLimit-Limit" in r.headers
    assert "X-RateLimit-Remaining" in r.headers
    assert "X-RateLimit-Reset" in r.headers


def test_does_not_block_when_disabled(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_PER_MINUTE", "1")
    monkeypatch.setenv("RATE_LIMIT_BURST", "1")

    c = _client()
    h = {"X-Tenant-ID": "t1", "X-Bot-ID": "b1"}
    # Even if we spam, it should not return 429
    for _ in range(5):
        assert c.get("/health", headers=h).status_code == 200


def test_blocks_when_enabled(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_PER_MINUTE", "2")
    monkeypatch.setenv("RATE_LIMIT_BURST", "2")

    c = _client()
    h = {"X-Tenant-ID": "t2", "X-Bot-ID": "b2"}

    assert c.get("/health", headers=h).status_code == 200
    assert c.get("/health", headers=h).status_code == 200
    r3 = c.get("/health", headers=h)
    assert r3.status_code == 429
    assert r3.json()["detail"] == "rate limit exceeded"
    assert r3.headers["X-RateLimit-Remaining"] == "0"
    assert "X-RateLimit-Reset" in r3.headers


def test_refill_allows_after_wait(monkeypatch):
    # 1 per minute, burst 1. To keep the test quick, use 60/minute (~1/sec)
    # so at least one token refills after ~1s.
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_PER_MINUTE", "60")
    monkeypatch.setenv("RATE_LIMIT_BURST", "1")

    c = _client()
    h = {"X-Tenant-ID": "t3", "X-Bot-ID": "b3"}

    assert c.get("/health", headers=h).status_code == 200
    r2 = c.get("/health", headers=h)
    assert r2.status_code == 429

    time.sleep(1.2)  # ~1 token refills
    r3 = c.get("/health", headers=h)
    assert r3.status_code == 200

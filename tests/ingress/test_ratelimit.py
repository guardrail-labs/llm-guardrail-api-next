from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.middleware.rate_limit import RateLimitMiddleware
from app.services import ratelimit as rl


def _make_app():
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware)

    @app.get("/echo")
    def echo():
        return {"ok": True}

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app


class _Clock:
    def __init__(self, t=0.0):
        self.t = t

    def now(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def _reset_globals(monkeypatch):
    monkeypatch.setattr(rl, "_global_enabled", None, raising=False)
    monkeypatch.setattr(rl, "_global_limiter", None, raising=False)


def test_under_limit_allows(monkeypatch):
    clk = _Clock(t=0.0)
    monkeypatch.setattr(rl, "_now", clk.now)
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_RPS", "2")
    monkeypatch.setenv("RATE_LIMIT_BURST", "2")
    _reset_globals(monkeypatch)

    app = _make_app()
    client = TestClient(app)
    headers = {"X-Tenant": "t1", "X-Bot": "b1"}

    r1 = client.get("/echo", headers=headers)
    r2 = client.get("/echo", headers=headers)
    assert r1.status_code == 200
    assert r2.status_code == 200

    r3 = client.get("/echo", headers=headers)
    assert r3.status_code == 429
    assert "Retry-After" in r3.headers

    clk.advance(0.5)
    r4 = client.get("/echo", headers=headers)
    assert r4.status_code == 200


def test_separate_buckets_by_tenant_bot(monkeypatch):
    clk = _Clock(t=0.0)
    monkeypatch.setattr(rl, "_now", clk.now)
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_RPS", "1")
    monkeypatch.setenv("RATE_LIMIT_BURST", "1")
    _reset_globals(monkeypatch)

    app = _make_app()
    client = TestClient(app)

    r1 = client.get("/echo", headers={"X-Tenant": "t1", "X-Bot": "b1"})
    assert r1.status_code == 200

    r2 = client.get("/echo", headers={"X-Tenant": "t2", "X-Bot": "b1"})
    assert r2.status_code == 200

    r3 = client.get("/echo", headers={"X-Tenant": "t1", "X-Bot": "b1"})
    assert r3.status_code == 429


def test_headers_present_and_health_skipped(monkeypatch):
    clk = _Clock(t=0.0)
    monkeypatch.setattr(rl, "_now", clk.now)
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_RPS", "1")
    monkeypatch.setenv("RATE_LIMIT_BURST", "1")
    _reset_globals(monkeypatch)

    app = _make_app()
    client = TestClient(app)

    ok = client.get("/echo", headers={"X-Guardrail-Tenant": "acme", "X-Guardrail-Bot": "web"})
    assert ok.status_code == 200

    blocked = client.get("/echo", headers={"X-Guardrail-Tenant": "acme", "X-Guardrail-Bot": "web"})
    assert blocked.status_code == 429
    assert blocked.headers.get("Retry-After") is not None
    assert "X-RateLimit-Limit" in blocked.headers
    assert blocked.headers.get("X-RateLimit-Remaining") == "0"

    health = client.get("/health")
    assert health.status_code == 200

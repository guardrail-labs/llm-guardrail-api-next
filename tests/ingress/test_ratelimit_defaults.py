from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.middleware.rate_limit import RateLimitMiddleware


def _make_app():
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware)

    @app.get("/echo")
    def echo():
        return {"ok": True}

    return app


def test_default_is_opt_in(monkeypatch):
    # Ensure no env enables it
    for k in ("RATE_LIMIT_ENABLED", "RATE_LIMIT_RPS", "RATE_LIMIT_BURST"):
        monkeypatch.delenv(k, raising=False)

    app = _make_app()
    c = TestClient(app)
    # Multiple back-to-back calls should NOT rate-limit by default
    r1 = c.get("/echo")
    r2 = c.get("/echo")
    assert r1.status_code == 200
    assert r2.status_code == 200

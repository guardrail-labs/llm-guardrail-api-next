from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from starlette.testclient import TestClient

from app.middleware.rate_limit import RateLimitMiddleware


def _make_app(per_key: int = 2, per_ip: int = 3) -> FastAPI:
    app = FastAPI()
    app.add_middleware(
        RateLimitMiddleware,
        enabled=True,
        per_api_key_per_min=per_key,  # small numbers to exercise behavior
        per_ip_per_min=per_ip,
    )

    @app.get("/ping")
    def ping() -> PlainTextResponse:
        return PlainTextResponse("pong")

    return app


def test_rate_limit_by_api_key_and_ip():
    app = _make_app(per_key=2, per_ip=1000)  # essentially ignore IP limit
    c = TestClient(app)

    # With a key, only 2 requests per minute allowed
    h = {"x-api-key": "abc123"}
    assert c.get("/ping", headers=h).status_code == 200
    assert c.get("/ping", headers=h).status_code == 200
    r3 = c.get("/ping", headers=h)
    assert r3.status_code == 429
    assert "Retry-After" in r3.headers
    assert r3.json()["mode"] == "rate_limited"

    # Different key should have its own bucket
    h2 = {"x-api-key": "def456"}
    assert c.get("/ping", headers=h2).status_code == 200
    assert c.get("/ping", headers=h2).status_code == 200
    assert c.get("/ping", headers=h2).status_code == 429


def test_rate_limit_by_ip_when_no_key():
    app = _make_app(per_key=1000, per_ip=2)
    c = TestClient(app)

    # No key => uses IP bucket (client shares same IP in tests)
    assert c.get("/ping").status_code == 200
    assert c.get("/ping").status_code == 200
    r = c.get("/ping")
    assert r.status_code == 429
    assert r.json()["mode"] == "rate_limited"
    assert "Retry-After" in r.headers


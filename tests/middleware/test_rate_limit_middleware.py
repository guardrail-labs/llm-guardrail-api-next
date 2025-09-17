from __future__ import annotations

from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from starlette.testclient import TestClient

from app.middleware.rate_limit import RateLimitMiddleware
from app.services import ratelimit as rl


def _make_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware)

    @app.get("/ping")
    def ping() -> PlainTextResponse:
        return PlainTextResponse("pong")

    return app


def _reset(monkeypatch):
    monkeypatch.setattr(rl, "_global_enabled", None, raising=False)
    monkeypatch.setattr(rl, "_global_limiter", None, raising=False)


def test_rate_limit_disabled_env(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    _reset(monkeypatch)

    app = _make_app()
    client = TestClient(app)

    for _ in range(5):
        resp = client.get("/ping", headers={"X-Tenant": "t", "X-Bot": "b"})
        assert resp.status_code == 200


def test_rate_limit_reads_settings(monkeypatch):
    _reset(monkeypatch)

    settings = SimpleNamespace(
        ingress=SimpleNamespace(
            rate_limit=SimpleNamespace(enabled=True, rps=1.0, burst=1.0)
        )
    )

    app = _make_app()
    app.state.settings = settings
    client = TestClient(app)

    headers = {"X-Tenant": "acme", "X-Bot": "web"}
    assert client.get("/ping", headers=headers).status_code == 200
    blocked = client.get("/ping", headers=headers)
    assert blocked.status_code == 429
    body = blocked.json()
    assert body["retry_after_seconds"] >= 1

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _make_app() -> FastAPI:
    app = FastAPI()

    from app.routes.health import router as health_router

    app.include_router(health_router)

    from app.middleware.rate_limit import RateLimitMiddleware

    app.add_middleware(RateLimitMiddleware)

    @app.get("/echo")
    def echo() -> dict[str, bool]:
        return {"ok": True}

    return app


def _reset_ratelimit_globals(monkeypatch: pytest.MonkeyPatch) -> None:
    import app.services.ratelimit as rl

    # Ensure we don't reuse a cached limiter from prior tests.
    monkeypatch.setattr(rl, "_global_enabled", None, raising=False)
    monkeypatch.setattr(rl, "_global_limiter", None, raising=False)
    monkeypatch.setattr(rl, "_global_enforce_unknown", None, raising=False)


def test_readyz_and_livez_bypass_ratelimit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_RPS", "1")
    monkeypatch.setenv("RATE_LIMIT_BURST", "1")
    monkeypatch.setenv("RATE_LIMIT_ENFORCE_UNKNOWN", "true")

    _reset_ratelimit_globals(monkeypatch)

    app = _make_app()
    client = TestClient(app)

    assert client.get("/readyz").status_code in (200, 503)
    assert client.get("/livez").status_code == 200

    first = client.get("/echo")
    second = client.get("/echo")
    assert first.status_code == 200
    assert second.status_code == 429

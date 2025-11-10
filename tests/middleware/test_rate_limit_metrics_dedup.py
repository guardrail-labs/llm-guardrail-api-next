from __future__ import annotations

import importlib
import sys
import types

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _app() -> FastAPI:
    app = FastAPI()

    @app.get("/echo")
    def echo() -> dict[str, bool]:
        return {"ok": True}

    from app.middleware.rate_limit import RateLimitMiddleware

    app.add_middleware(RateLimitMiddleware)
    return app


def test_rate_limit_does_not_emit_generic_decision_metric(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_RPS", "1")
    monkeypatch.setenv("RATE_LIMIT_BURST", "1")
    monkeypatch.setenv("RATE_LIMIT_ENFORCE_UNKNOWN", "true")

    sentinel = types.SimpleNamespace(
        inc=lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("metrics_decisions.inc() should not be called in RateLimitMiddleware"),
        ),
        inc_redact=lambda *a, **k: None,
    )
    monkeypatch.setitem(sys.modules, "app.observability.metrics_decisions", sentinel)

    import app.services.ratelimit as ratelimit

    importlib.reload(ratelimit)
    import app.middleware.rate_limit as rate_limit_mod

    importlib.reload(rate_limit_mod)

    app = _app()
    client = TestClient(app)

    r1 = client.get("/echo")
    assert r1.status_code == 200

    r2 = client.get("/echo")
    assert r2.status_code == 429

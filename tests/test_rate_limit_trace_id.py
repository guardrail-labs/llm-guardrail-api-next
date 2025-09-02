from __future__ import annotations

import importlib

from fastapi.testclient import TestClient


def _reload_app():
    import app.telemetry.tracing as tracing
    importlib.reload(tracing)
    import app.middleware.rate_limit as rl
    importlib.reload(rl)
    import app.main as main
    importlib.reload(main)
    return main.app


def test_ratelimit_includes_trace_id(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_PER_MINUTE", "1")
    monkeypatch.setenv("RATE_LIMIT_BURST", "1")

    app = _reload_app()
    import app.middleware.rate_limit as rl
    monkeypatch.setattr(rl, "_get_trace_id", lambda: "trace-abc")

    client = TestClient(app)

    # First request allowed
    resp1 = client.get("/health")
    assert resp1.status_code == 200

    # Second should be rate limited and include trace id
    resp2 = client.get("/health")
    assert resp2.status_code == 429
    assert resp2.headers.get("X-Trace-ID") == "trace-abc"
    body = resp2.json()
    assert body["trace_id"] == "trace-abc"
    assert body["request_id"]

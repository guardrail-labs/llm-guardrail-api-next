from __future__ import annotations

import importlib

from fastapi.testclient import TestClient


def _client():
    import app.telemetry.metrics as metrics

    importlib.reload(metrics)
    import app.main as main

    importlib.reload(main)
    return TestClient(main.app)


def test_audit_events_include_sizes(monkeypatch):
    captured = {}

    # intercept the forwarder to capture payload
    import app.routes.guardrail as guardrail

    def fake_emit(payload):
        captured.update(payload)

    monkeypatch.setattr(guardrail, "emit_audit_event", fake_emit)

    c = _client()
    headers = {
        "X-API-Key": "k",
        "X-Tenant-ID": "t",
        "X-Bot-ID": "b",
        "Content-Type": "application/json",
    }

    r = c.post("/guardrail/evaluate", json={"text": "hello world"}, headers=headers)
    assert r.status_code == 200

    # fields present and sane
    assert "payload_bytes" in captured
    assert "sanitized_bytes" in captured
    assert isinstance(captured["payload_bytes"], int)
    assert isinstance(captured["sanitized_bytes"], int)
    assert captured["payload_bytes"] >= 0
    assert captured["sanitized_bytes"] >= 0

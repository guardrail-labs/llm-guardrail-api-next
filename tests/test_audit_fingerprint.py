from __future__ import annotations

import importlib

from fastapi.testclient import TestClient


def _client():
    import app.telemetry.metrics as metrics

    importlib.reload(metrics)
    import app.main as main

    importlib.reload(main)
    return TestClient(main.app)


def test_audit_events_include_fingerprint(monkeypatch):
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
    assert captured.get("hash_fingerprint")
    assert isinstance(captured["hash_fingerprint"], str)
    assert len(captured["hash_fingerprint"]) > 8  # looks like a hash

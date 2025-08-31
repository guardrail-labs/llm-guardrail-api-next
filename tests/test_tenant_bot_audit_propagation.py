from __future__ import annotations

import importlib
from fastapi.testclient import TestClient
import app.routes.guardrail as guardrail


def _client():
    import app.main as main
    importlib.reload(main)
    return TestClient(main.app)


def test_ingress_evaluate_includes_tenant_bot(monkeypatch):
    captured = {}

    def fake_emit(payload):
        captured.update(payload)

    # Patch the symbol used by routes (imported alias)
    monkeypatch.setattr(guardrail, "emit_audit_event", fake_emit)

    c = _client()
    h = {
        "X-API-Key": "k",
        "X-Tenant-ID": "acme",
        "X-Bot-ID": "bot-a",
        "Content-Type": "application/json",
    }
    r = c.post("/guardrail/evaluate", json={"text": "hello"}, headers=h)
    assert r.status_code == 200
    assert captured.get("tenant_id") == "acme"
    assert captured.get("bot_id") == "bot-a"
    assert captured.get("direction") == "ingress"


def test_egress_includes_tenant_bot(monkeypatch):
    captured = {}

    def fake_emit(payload):
        captured.update(payload)

    monkeypatch.setattr(guardrail, "emit_audit_event", fake_emit)

    c = _client()
    h = {
        "X-API-Key": "k",
        "X-Tenant-ID": "globex",
        "X-Bot-ID": "bot-z",
        "Content-Type": "application/json",
    }
    r = c.post("/guardrail/egress_evaluate", json={"text": "out"}, headers=h)
    assert r.status_code == 200
    assert captured.get("tenant_id") == "globex"
    assert captured.get("bot_id") == "bot-z"
    assert captured.get("direction") == "egress"


def test_multipart_includes_tenant_bot(monkeypatch):
    captured = {}

    def fake_emit(payload):
        captured.update(payload)

    monkeypatch.setattr(guardrail, "emit_audit_event", fake_emit)

    c = _client()
    h = {
        "X-API-Key": "k",
        "X-Tenant-ID": "acme",
        "X-Bot-ID": "bot-m",
    }
    # No files, just text form field
    r = c.post(
        "/guardrail/evaluate_multipart",
        data={"text": "hi"},
        headers=h,
    )
    assert r.status_code == 200
    assert captured.get("tenant_id") == "acme"
    assert captured.get("bot_id") == "bot-m"
    assert captured.get("direction") == "ingress"

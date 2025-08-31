from __future__ import annotations

import os
from typing import Any, Dict, List
from fastapi.testclient import TestClient
from app.main import app

# We'll monkeypatch the forwarder's _post to capture emitted payloads
from app.services import audit_forwarder as af

client = TestClient(app)


def test_forwarder_emits_on_ingress_and_egress(monkeypatch):
    # Enable forwarder with a dummy URL
    monkeypatch.setenv("AUDIT_FORWARD_ENABLED", "true")
    monkeypatch.setenv(
        "AUDIT_FORWARD_URL", "http://example.local/enterprise/audit/ingest"
    )
    monkeypatch.setenv("AUDIT_FORWARD_API_KEY", "unit-test-key")

    captured: List[Dict[str, Any]] = []

    def fake_post(url: str, api_key: str, payload: Dict[str, Any]):
        captured.append({"url": url, "api_key": api_key, "payload": payload})
        return (200, "ok")

    # Patch the raw post
    af._post = fake_post

    # Ingress call
    r1 = client.post(
        "/guardrail/evaluate", json={"text": "hi sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ"}
    )
    assert r1.status_code == 200

    # Egress call
    r2 = client.post(
        "/guardrail/egress_evaluate",
        json={"text": "-----BEGIN PRIVATE KEY----- ..."},
    )
    assert r2.status_code == 200

    # Multipart call (no files)
    r3 = client.post("/guardrail/evaluate_multipart", data={"text": "hello"})
    assert r3.status_code == 200

    # We should have 3 emits
    assert len(captured) == 3
    # Basic shape checks
    for item in captured:
        assert item["url"].endswith("/enterprise/audit/ingest")
        p = item["payload"]
        assert "decision" in p
        assert "direction" in p
        assert "rule_hits" in p or p.get("rule_hits") is None
        assert "redaction_count" in p


def test_forwarder_noop_when_disabled(monkeypatch):
    monkeypatch.delenv("AUDIT_FORWARD_ENABLED", raising=False)
    monkeypatch.setenv(
        "AUDIT_FORWARD_URL", "http://example.local/enterprise/audit/ingest"
    )
    monkeypatch.setenv("AUDIT_FORWARD_API_KEY", "unit-test-key")

    emitted = {"count": 0}

    def fake_post(url: str, api_key: str, payload: Dict[str, Any]):
        emitted["count"] += 1
        return (200, "ok")

    af._post = fake_post

    r = client.post("/guardrail/evaluate", json={"text": "hello"})
    assert r.status_code == 200
    assert emitted["count"] == 0

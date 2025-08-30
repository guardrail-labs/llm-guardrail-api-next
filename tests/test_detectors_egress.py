from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_egress_allows_with_redactions():
    text = "Contact me at jane.doe@example.com or call 555-123-4567"
    r = client.post("/guardrail/egress_evaluate", json={"text": text})
    assert r.status_code == 200
    body = r.json()
    assert body["action"] == "allow"
    assert "[REDACTED:EMAIL]" in body["text"]
    assert "[REDACTED:PHONE]" in body["text"]
    assert "pi:*" in (body.get("rule_hits") or [])


def test_egress_denies_on_private_key_envelope():
    text = "-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----"
    r = client.post("/guardrail/egress_evaluate", json={"text": text})
    assert r.status_code == 200
    body = r.json()
    assert body["action"] == "deny"
    assert body["text"] == ""
    assert "policy:deny:*" in (body.get("rule_hits") or [])


def test_egress_debug_explanations_when_header_set():
    text = "email a@b.co"
    r = client.post(
        "/guardrail/egress_evaluate",
        json={"text": text},
        headers={"X-Debug": "1"},
    )
    assert r.status_code == 200
    body = r.json()
    assert "debug" in body
    assert "explanations" in body["debug"]

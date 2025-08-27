from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_ok():
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert isinstance(body["requests_total"], (int, float))
    assert isinstance(body["decisions_total"], (int, float))
    assert isinstance(body["rules_version"], str)


def test_metrics_exposes_counters():
    # Hit an endpoint first so counters tick.
    client.post("/guardrail/evaluate", json={"text": "hello"})
    r = client.get("/metrics")
    assert r.status_code == 200
    # Prometheus text exposition should include our metrics names.
    txt = r.text
    assert "guardrail_requests_total" in txt
    assert "guardrail_decisions_total" in txt
    assert "guardrail_redactions_total" in txt


def test_guardrail_evaluate_basic_and_redaction():
    # Include a token-like string to trigger redaction path.
    payload = {
        "request_id": "test-req-123",
        "text": "secret sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ is here",
    }
    r = client.post("/guardrail/evaluate", json=payload)
    assert r.status_code == 200
    body = r.json()

    # Contract checks
    assert body["request_id"] == "test-req-123"
    assert body["action"] == "allow"
    assert isinstance(body["decisions"], list)

    # Redaction applied
    assert "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ" not in body["transformed_text"]
    assert "[REDACTED:OPENAI_KEY]" in body["transformed_text"]

    # When redactions happen, a decision should be present
    types = {d.get("type") for d in body["decisions"] if isinstance(d, dict)}
    assert "redaction" in types


def test_admin_policy_reload_contract():
    r = client.post("/admin/policy/reload")
    assert r.status_code == 200
    body = r.json()
    assert body.get("reloaded") is True
    assert isinstance(body.get("version"), str)
    assert isinstance(body.get("rules_loaded"), int)

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_legacy_guardrail_redaction_header() -> None:
    payload = {"prompt": "secret sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ is here"}
    r = client.post("/guardrail", json=payload, headers={"X-API-Key": "anything"})
    assert r.status_code == 200
    assert r.headers.get("X-Guardrail-Ingress-Redactions") == "1"
    body = r.json()
    assert body["redactions"] == 1


def test_ingress_evaluate_redaction_header() -> None:
    payload = {"text": "secret sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ is here"}
    r = client.post("/guardrail/evaluate", json=payload)
    assert r.status_code == 200
    assert r.headers.get("X-Guardrail-Ingress-Redactions") == "1"
    body = r.json()
    assert body["redactions"] == 1


def test_egress_evaluate_redaction_header() -> None:
    payload = {"text": "secret sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ is here"}
    r = client.post("/guardrail/egress_evaluate", json=payload)
    assert r.status_code == 200
    assert r.headers.get("X-Guardrail-Egress-Redactions") == "1"
    body = r.json()
    assert body["redactions"] == 1

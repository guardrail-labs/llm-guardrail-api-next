from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
HDR = "X-Guardrail-Policy-Version"


def test_policy_header_on_legacy_guardrail() -> None:
    r = client.post(
        "/guardrail",
        json={"prompt": "hi"},
        headers={"X-API-Key": "anything"},  # legacy route only checks presence
    )
    assert r.status_code == 200
    assert HDR in r.headers
    assert r.headers[HDR]


def test_policy_header_on_ingress_evaluate() -> None:
    r = client.post("/guardrail/evaluate", json={"text": "hello"})
    assert r.status_code == 200
    assert HDR in r.headers
    assert r.headers[HDR]


def test_policy_header_on_egress_evaluate() -> None:
    r = client.post("/guardrail/egress_evaluate", json={"text": "ok"})
    assert r.status_code == 200
    assert HDR in r.headers
    assert r.headers[HDR]


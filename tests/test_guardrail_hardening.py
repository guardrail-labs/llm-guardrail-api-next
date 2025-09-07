from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _post_guardrail(prompt: str):
    # Legacy route requires an API key header presence; any value is fine
    return client.post(
        "/guardrail",
        json={"prompt": prompt},
        headers={"X-API-Key": "k"},
    )


def test_payload_blob_boundary():
    # The legacy policy blocks long base64-ish blobs: regex {200,}
    s199 = "A" * 199
    s200 = "A" * 200
    s201 = "A" * 201

    r_ok = _post_guardrail(f"pre {s199} post")
    assert r_ok.status_code == 200
    assert r_ok.json().get("decision") == "allow"

    r_block_200 = _post_guardrail(f"pre {s200} post")
    assert r_block_200.status_code == 200
    assert r_block_200.json().get("decision") == "block"

    r_block_201 = _post_guardrail(f"pre {s201} post")
    assert r_block_201.status_code == 200
    assert r_block_201.json().get("decision") == "block"


def test_egress_deny_increments_metrics():
    # Private key envelope triggers egress deny
    payload = {"text": "-----BEGIN PRIVATE KEY----- X -----END PRIVATE KEY-----"}
    r = client.post("/guardrail/egress_evaluate", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert body.get("action") == "deny"

    # Metrics should include a deny family increment
    m = client.get("/metrics")
    assert m.status_code == 200
    text = m.text
    assert 'guardrail_decisions_family_total{family="deny"}' in text


def test_policy_version_header_present_on_guardrail_evaluate():
    r = client.post(
        "/guardrail/evaluate",
        json={"text": "hello"},
        headers={"X-Tenant-ID": "default", "X-Bot-ID": "default"},
    )
    assert r.status_code == 200
    # Parity header is present and non-empty
    assert "X-Guardrail-Policy-Version" in r.headers
    assert r.headers["X-Guardrail-Policy-Version"]

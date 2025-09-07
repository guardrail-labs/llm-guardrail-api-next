import importlib
import os

from fastapi.testclient import TestClient


def _make_client():
    os.environ["API_KEY"] = "unit-test-key"
    import app.config as cfg

    importlib.reload(cfg)
    import app.main as main

    importlib.reload(main)
    return TestClient(main.build_app())


def test_output_smoke_allows_200():
    client = _make_client()
    r = client.post(
        "/guardrail/output",
        json={"output": "harmless text"},
        headers={"X-API-Key": "unit-test-key"},
    )
    assert r.status_code == 200
    body = r.json()
    assert "decision" in body
    assert "transformed_text" in body


def test_output_redaction_applied():
    os.environ["REDACT_SECRETS"] = "true"
    client = _make_client()
    payload = {"output": "leak: sk-1234567890abcdefghijklmnop and -----BEGIN PRIVATE KEY-----"}
    r = client.post(
        "/guardrail/output",
        json=payload,
        headers={"X-API-Key": "unit-test-key"},
    )
    assert r.status_code == 200
    tx = r.json()["transformed_text"]
    assert "sk-1234" not in tx
    assert "BEGIN PRIVATE KEY" not in tx


def test_output_size_limit_413():
    os.environ["OUTPUT_MAX_CHARS"] = "32"
    client = _make_client()
    big = "Z" * 64
    r = client.post(
        "/guardrail/output",
        json={"output": big},
        headers={"X-API-Key": "unit-test-key"},
    )
    assert r.status_code == 413
    assert "Output too large" in r.json().get("detail", "")

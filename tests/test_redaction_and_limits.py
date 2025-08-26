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


def test_redacts_secrets_in_transformed_text():
    os.environ["REDACT_SECRETS"] = "true"

    client = _make_client()
    prompt = (
        "Here is a key sk-1234567890abcdefghijklmnop and an AKIAABCDEFGHIJKLMNOP.\n"
        "Also a header -----BEGIN PRIVATE KEY----- and footer -----END PRIVATE KEY-----"
    )
    r = client.post("/guardrail", json={"prompt": prompt}, headers={"X-API-Key": "unit-test-key"})
    assert r.status_code == 200
    body = r.json()

    # Decision still blocks due to secret-like patterns
    assert body["decision"] == "block"

    # Confirm masks present and raw tokens absent
    tx = body["transformed_text"]
    assert "sk-1234" not in tx
    assert "AKIA" not in tx
    assert "BEGIN PRIVATE KEY" not in tx
    assert "[REDACTED:OPENAI_KEY]" in tx
    assert "[REDACTED:AWS_ACCESS_KEY_ID]" in tx
    assert "[REDACTED:PRIVATE_KEY]" in tx

    # Metrics surface redaction counter
    m = client.get("/metrics")
    assert m.status_code == 200
    assert "guardrail_redactions_total" in m.text


def test_prompt_size_limit_returns_413():
    os.environ["MAX_PROMPT_CHARS"] = "64"

    client = _make_client()
    big = "X" * 100
    r = client.post("/guardrail", json={"prompt": big}, headers={"X-API-Key": "unit-test-key"})
    assert r.status_code == 413
    assert "Prompt too large" in r.json()["detail"]


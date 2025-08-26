import os
import importlib
from fastapi.testclient import TestClient


def _make_client():
    # Provide a key to the app for tests
    os.environ["API_KEY"] = "unit-test-key"

    # Reload config and main so they pick up the env var
    import app.config as cfg
    importlib.reload(cfg)
    import app.main as main
    importlib.reload(main)

    return TestClient(main.build_app())


def test_guardrail_allows_by_default():
    client = _make_client()
    payload = {"prompt": "Hello, world!"}
    # Provide key via header (accepted header #1)
    r = client.post("/guardrail", json=payload, headers={"X-API-Key": "unit-test-key"})
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "allow"
    assert isinstance(body["request_id"], str)
    assert "policy_version" in body

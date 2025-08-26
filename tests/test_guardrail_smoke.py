import importlib
import os

from fastapi.testclient import TestClient


def _make_client():
    # Provide an API key for the app during tests
    os.environ["API_KEY"] = "unit-test-key"

    # Reload config/main so settings pick up the env var before app build
    import app.config as cfg
    importlib.reload(cfg)
    import app.main as main
    importlib.reload(main)

    return TestClient(main.build_app())


def test_guardrail_allows_by_default():
    client = _make_client()
    payload = {"prompt": "Hello, world!"}

    # Include the API key (either header form is accepted)
    r = client.post("/guardrail", json=payload, headers={"X-API-Key": "unit-test-key"})
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "allow"
    assert isinstance(body["request_id"], str)
    assert "policy_version" in body

    r2 = client.post(
        "/guardrail",
        json=payload,
        headers={"Authorization": "Bearer unit-test-key"},
    )
    assert r2.status_code == 200

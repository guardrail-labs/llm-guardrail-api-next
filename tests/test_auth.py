import importlib
import os

from fastapi.testclient import TestClient


def _make_client(monkeypatch):
    os.environ["API_KEY"] = "unit-test-key"
    monkeypatch.setenv("GUARDRAIL_DISABLE_AUTH", "0")

    import app.config as cfg
    importlib.reload(cfg)
    import app.main as main
    importlib.reload(main)

    return TestClient(main.build_app())


def test_guardrail_requires_api_key(monkeypatch):
    client = _make_client(monkeypatch)
    r = client.post("/guardrail", json={"prompt": "hi"})
    assert r.status_code == 401
    assert r.json()["detail"] == "Unauthorized"


def test_guardrail_accepts_x_api_key(monkeypatch):
    client = _make_client(monkeypatch)
    r = client.post("/guardrail", json={"prompt": "hi"}, headers={"X-API-Key": "unit-test-key"})
    assert r.status_code == 200


def test_guardrail_accepts_bearer_token(monkeypatch):
    client = _make_client(monkeypatch)
    r = client.post(
        "/guardrail",
        json={"prompt": "hi"},
        headers={"Authorization": "Bearer unit-test-key"},
    )
    assert r.status_code == 200

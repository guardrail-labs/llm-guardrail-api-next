from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.routes import admin_overview as ao


def _app() -> FastAPI:
    app = FastAPI()
    app.include_router(ao.router)
    return app


def test_admin_overview_200(monkeypatch):
    # allow dev mode (no key/guard)
    app = _app()
    client = TestClient(app)
    response = client.get("/admin")
    assert response.status_code == 200
    assert "Guardrail Admin" in response.text


def test_policy_viewer_renders(monkeypatch):
    # stub merged policy
    dummy = {
        "rules": {"redact": [{"id": "k", "pattern": "x", "replacement": "y"}]},
        "secrets": {"api_key": "sk_123"},
    }
    monkeypatch.setattr(ao, "_get_merged_policy", lambda: dummy)

    app = _app()
    client = TestClient(app)
    response = client.get("/admin/policy/current")
    assert response.status_code == 200
    # redacted secret should not appear
    assert "sk_123" not in response.text
    assert "***" in response.text

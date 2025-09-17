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


def test_policy_viewer_uses_real_api(monkeypatch):
    # Fake a policy service exposing the real API
    dummy = {
        "rules": {"redact": [{"id": "k", "pattern": "x", "replacement": "y"}]},
        "secrets": {"api_key": "sk_123"},
    }

    import sys
    import types
    from importlib import import_module

    fake_pol = types.SimpleNamespace(
        get_active_policy=lambda: dummy,
        current_rules_version=lambda: "v-abcdef1234",
    )
    monkeypatch.setitem(sys.modules, "app.services.policy", fake_pol)
    services_pkg = import_module("app.services")
    monkeypatch.setattr(services_pkg, "policy", fake_pol, raising=False)

    app = _app()
    c = TestClient(app)

    # Overview shows version from current_rules_version()
    r_over = c.get("/admin")
    assert r_over.status_code == 200
    assert "v-abcdef1234" in r_over.text

    # Policy page shows redacted body and same version
    r = c.get("/admin/policy/current")
    assert r.status_code == 200
    assert "v-abcdef1234" in r.text
    assert "sk_123" not in r.text
    assert "***" in r.text

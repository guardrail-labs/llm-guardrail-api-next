from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.routes import admin_decisions_api as dec


def _app():
    app = FastAPI()
    app.include_router(dec.router)
    return app


def test_admin_gate_requires_key_when_configured(monkeypatch):
    # Configure fallback admin key
    monkeypatch.setenv("ADMIN_API_KEY", "secret123")
    # Simulate no shared guard configured
    real_import = dec.importlib.import_module

    def fake_import(name, *args, **kwargs):
        if name in {
            "app.routes.admin_rbac",
            "app.security.admin_auth",
            "app.routes.admin_common",
            "app.security.admin",
            "app.security.auth",
        }:
            raise ImportError("guard not configured")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(dec.importlib, "import_module", fake_import)
    app = _app()
    c = TestClient(app)

    # Without key → 401
    r1 = c.get("/admin/api/decisions")
    assert r1.status_code == 401

    # With wrong key → 401
    r2 = c.get("/admin/api/decisions", headers={"X-Admin-Key": "nope"})
    assert r2.status_code == 401

    # With correct key → 200
    r3 = c.get("/admin/api/decisions", headers={"X-Admin-Key": "secret123"})
    assert r3.status_code == 200


def test_admin_gate_open_when_not_configured(monkeypatch):
    # Ensure no env/setting is present
    monkeypatch.delenv("ADMIN_API_KEY", raising=False)
    monkeypatch.delenv("GUARDRAIL_ADMIN_KEY", raising=False)
    app = _app()
    c = TestClient(app)
    r = c.get("/admin/api/decisions")
    assert r.status_code == 200  # dev-friendly default


def test_admin_gate_uses_env_override(monkeypatch):
    # Fake a guard via a temporary module using env override
    import sys
    import types

    fake = types.ModuleType("tests.fake_admin_guard")
    calls = {"count": 0}

    def require_admin_dep(request):
        calls["count"] += 1
        # no exception -> authorized
        return None

    fake.require_admin = require_admin_dep
    sys.modules["tests.fake_admin_guard"] = fake

    monkeypatch.setenv("ADMIN_GUARD", "tests.fake_admin_guard:require_admin")
    # Ensure no fallback key interferes
    monkeypatch.delenv("ADMIN_API_KEY", raising=False)
    monkeypatch.delenv("GUARDRAIL_ADMIN_KEY", raising=False)

    from importlib import reload

    from app.routes import admin_decisions_api as dec

    reload(dec)  # pick up env override in loader

    app = _app()
    c = TestClient(app)
    r = c.get("/admin/api/decisions")
    assert r.status_code == 200
    # ensure our guard was called
    assert calls["count"] >= 1

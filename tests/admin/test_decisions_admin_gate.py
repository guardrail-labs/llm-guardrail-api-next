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

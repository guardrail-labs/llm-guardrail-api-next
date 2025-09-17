from __future__ import annotations

import types

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.routes import admin_policy_packs as appmod


def _app() -> FastAPI:
    app = FastAPI()
    app.include_router(appmod.router)
    return app


def test_packs_page_renders(monkeypatch):
    fake_pol = types.SimpleNamespace(get_active_policy=lambda: {"rules": {"redact": [{"id": "x"}]}})
    monkeypatch.setattr(appmod, "_get_policy_module", lambda: fake_pol)
    app = _app()
    client = TestClient(app)
    response = client.get("/admin/policy/packs")
    assert response.status_code == 200
    assert "Policy Packs" in response.text

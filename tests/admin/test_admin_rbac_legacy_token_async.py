from __future__ import annotations

from typing import Any

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.security import rbac


@pytest.fixture()
def app_factory(monkeypatch):
    monkeypatch.setenv("ADMIN_AUTH_MODE", "cookie")

    app = FastAPI()

    @app.post("/admin/api/webhooks/dlq/purge")
    async def _purge(_: dict[str, Any] = Depends(rbac.require_operator)) -> dict[str, str]:
        return {"status": "ok"}

    return lambda: app


def _install_async_legacy_auth(monkeypatch):
    # Force auth mode that requires authentication
    monkeypatch.setenv("ADMIN_AUTH_MODE", "cookie")

    # Async legacy verifier that only accepts "Bearer ok"
    async def require_auth(request):
        auth = request.headers.get("authorization") or ""
        if auth.strip() != "Bearer ok":
            raise Exception("invalid token")
        return True

    # Install (or create) module
    try:
        from app.security import admin_auth

        monkeypatch.setattr(admin_auth, "require_auth", require_auth, raising=True)
    except Exception:
        import sys
        import types

        mod = types.ModuleType("app.security.admin_auth")
        mod.require_auth = require_auth
        sys.modules["app.security.admin_auth"] = mod


def test_async_legacy_auth_rejected_without_token(app_factory, monkeypatch):
    _install_async_legacy_auth(monkeypatch)
    c = TestClient(app_factory())
    r = c.post("/admin/api/webhooks/dlq/purge", json={"csrf_token": "ok"})
    assert r.status_code in (401, 403)


def test_async_legacy_auth_accepts_valid_token(app_factory, monkeypatch):
    _install_async_legacy_auth(monkeypatch)
    c = TestClient(app_factory())
    r = c.post(
        "/admin/api/webhooks/dlq/purge",
        json={"csrf_token": "ok"},
        headers={"Authorization": "Bearer ok"},
    )
    assert 200 <= r.status_code < 300

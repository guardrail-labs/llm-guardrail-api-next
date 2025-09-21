from __future__ import annotations

import importlib
import sys
from types import ModuleType
from typing import Any, Dict

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.security import rbac


@pytest.fixture()
def app_factory(monkeypatch):
    monkeypatch.setenv("ADMIN_AUTH_MODE", "cookie")

    app = FastAPI()

    @app.get("/protected")
    def _protected(user: Dict[str, Any] = Depends(rbac.require_operator)) -> Dict[str, Any]:
        return {"user": user}

    return lambda: app


def _as_legacy_token_ok(monkeypatch):
    monkeypatch.setenv("ADMIN_AUTH_MODE", "cookie")

    def ok(_request):
        return True

    try:
        admin_auth = importlib.import_module("app.security.admin_auth")
        monkeypatch.setattr(admin_auth, "require_auth", ok, raising=True)
    except Exception:
        mod = ModuleType("app.security.admin_auth")
        setattr(mod, "require_auth", ok)
        monkeypatch.setitem(sys.modules, "app.security.admin_auth", mod)


def test_legacy_token_passes_rbac_operator(app_factory, monkeypatch):
    _as_legacy_token_ok(monkeypatch)
    client = TestClient(app_factory())
    response = client.get(
        "/protected",
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200


def test_legacy_token_helper_returns_default_user(monkeypatch):
    _as_legacy_token_ok(monkeypatch)
    request = type("R", (), {"headers": {"Authorization": "Bearer token"}})()
    user = rbac._try_legacy_admin_token(request)
    assert user["role"] == "operator"

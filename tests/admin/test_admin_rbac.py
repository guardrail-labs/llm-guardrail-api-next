from __future__ import annotations

from fastapi.testclient import TestClient

import app.services.config_store as cfg
from app.main import create_app


def _client() -> TestClient:
    return TestClient(create_app())


def test_policy_reload_allowed_when_rbac_disabled(monkeypatch) -> None:
    monkeypatch.setattr(cfg, "is_admin_rbac_enabled", lambda: False)
    c = _client()
    response = c.post(
        "/admin/api/policy/reload",
        json={"csrf_token": "t"},
        cookies={"ui_csrf": "t"},
    )
    assert response.status_code == 200


def test_policy_reload_forbidden_without_key_when_enabled(monkeypatch) -> None:
    monkeypatch.setattr(cfg, "is_admin_rbac_enabled", lambda: True)
    monkeypatch.setattr(cfg, "get_admin_api_key", lambda: "secret123")
    c = _client()
    response = c.post(
        "/admin/api/policy/reload",
        json={"csrf_token": "t"},
        cookies={"ui_csrf": "t"},
    )
    assert response.status_code == 403


def test_policy_reload_allowed_with_header_key(monkeypatch) -> None:
    monkeypatch.setattr(cfg, "is_admin_rbac_enabled", lambda: True)
    monkeypatch.setattr(cfg, "get_admin_api_key", lambda: "secret123")
    c = _client()
    response = c.post(
        "/admin/api/policy/reload",
        headers={"X-Admin-Key": "secret123"},
        json={"csrf_token": "t"},
        cookies={"ui_csrf": "t"},
    )
    assert response.status_code == 200


def test_policy_reload_allowed_with_cookie_key(monkeypatch) -> None:
    monkeypatch.setattr(cfg, "is_admin_rbac_enabled", lambda: True)
    monkeypatch.setattr(cfg, "get_admin_api_key", lambda: "secret123")
    c = _client()
    response = c.post(
        "/admin/api/policy/reload",
        cookies={"ui_csrf": "t", "admin_key": "secret123"},
        json={"csrf_token": "t"},
    )
    assert response.status_code == 200

from __future__ import annotations

import importlib
from typing import Tuple

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.services.policy_validate_enforce import validate_text_for_reload


def _client_with_router(monkeypatch) -> Tuple[TestClient, object]:
    """Return a test client wired to the admin policy reload router."""

    import app.routes.admin_policy_api as api

    api = importlib.reload(api)
    monkeypatch.setattr(api, "require_admin", lambda request: None, raising=False)

    app = FastAPI()
    app.include_router(api.router)
    client = TestClient(app)
    return client, api


def test_validate_text_for_reload_warn_allows(monkeypatch):
    monkeypatch.setenv("POLICY_VALIDATE_ENFORCE", "warn")

    def fake_validator(text: str):
        return {
            "status": "fail",
            "issues": [
                {"severity": "error", "code": "yaml_parse", "message": "bad"},
            ],
        }

    monkeypatch.setattr(
        "app.services.policy_validate.validate_yaml_text", fake_validator, raising=True
    )
    allow, result = validate_text_for_reload("text")
    assert allow is True
    assert result["enforcement_mode"] == "warn"
    assert result["status"] == "fail"


def test_validate_text_for_reload_block_rejects(monkeypatch):
    monkeypatch.setenv("POLICY_VALIDATE_ENFORCE", "block")

    def fake_validator(text: str):
        return {
            "status": "fail",
            "issues": [
                {"severity": "error", "code": "yaml_parse", "message": "bad"},
            ],
        }

    monkeypatch.setattr(
        "app.services.policy_validate.validate_yaml_text", fake_validator, raising=True
    )
    allow, result = validate_text_for_reload("text")
    assert allow is False
    assert result["enforcement_mode"] == "block"


def test_policy_reload_warn_allows(monkeypatch):
    client, api = _client_with_router(monkeypatch)

    monkeypatch.setattr(api, "get_policy_packs", lambda: ["demo"], raising=False)
    monkeypatch.setattr(api, "merge_packs", lambda names: ({}, "hash", []), raising=False)
    monkeypatch.setattr(api, "force_reload", lambda: "123", raising=False)

    def fake_validate(text: str):
        return True, {"status": "ok", "issues": [], "enforcement_mode": "warn"}

    monkeypatch.setattr(api, "validate_text_for_reload", fake_validate, raising=False)

    client.cookies.set("ui_csrf", "token")
    res = client.post(
        "/admin/api/policy/reload",
        headers={"X-CSRF-Token": "token"},
        json={"csrf_token": "token"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["validation"]["enforcement_mode"] == "warn"
    assert data["version"] == "123"


def test_policy_reload_block_rejects_on_error(monkeypatch):
    client, api = _client_with_router(monkeypatch)

    monkeypatch.setattr(api, "get_policy_packs", lambda: ["demo"], raising=False)
    monkeypatch.setattr(api, "merge_packs", lambda names: ({}, "hash", []), raising=False)

    def fake_validate(text: str):
        return False, {
            "status": "fail",
            "issues": [
                {"severity": "error", "code": "yaml_parse", "message": "bad"},
            ],
            "enforcement_mode": "block",
        }

    monkeypatch.setattr(api, "validate_text_for_reload", fake_validate, raising=False)

    client.cookies.set("ui_csrf", "token")
    res = client.post(
        "/admin/api/policy/reload",
        headers={"X-CSRF-Token": "token"},
        json={"csrf_token": "token"},
    )
    assert res.status_code == 422
    data = res.json()
    assert data["status"] == "fail"
    assert data["validation"]["enforcement_mode"] == "block"

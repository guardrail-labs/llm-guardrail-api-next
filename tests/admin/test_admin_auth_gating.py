from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())


def test_admin_policies_requires_token_when_enabled(client, monkeypatch):
    monkeypatch.setenv("GUARDRAIL_DISABLE_AUTH", "0")
    monkeypatch.setenv("ADMIN_UI_AUTH", "1")
    monkeypatch.setenv("ADMIN_UI_TOKEN", "s3cr3t")

    r = client.get("/admin/policies/active")
    assert r.status_code == 401
    assert "WWW-Authenticate" in r.headers

    r2 = client.get("/admin/policies/active", headers={"Authorization": "Bearer s3cr3t"})
    assert r2.status_code == 200
    j = r2.json()
    assert "policy_version" in j


def test_admin_ui_html_public(client, monkeypatch):
    monkeypatch.setenv("GUARDRAIL_DISABLE_AUTH", "0")
    monkeypatch.setenv("ADMIN_UI_AUTH", "1")
    monkeypatch.setenv("ADMIN_UI_TOKEN", "s3cr3t")

    r = client.get("/admin/ui")
    assert r.status_code == 200
    assert "Active Policy" in r.text


def test_policy_preview_works(client, monkeypatch):
    # Disable auth for simplicity here
    monkeypatch.setenv("GUARDRAIL_DISABLE_AUTH", "1")

    body = {"env_overrides": {"EGRESS_SUMMARIZE_ENABLED": "1", "CLARIFY_HTTP_STATUS": "400"}}
    r = client.post("/admin/policies/preview", json=body)
    assert r.status_code == 200
    j = r.json()
    assert "preview" in j and "changed" in j
    assert j["changed"].get("EGRESS_SUMMARIZE_ENABLED", {}).get("after") == "1"

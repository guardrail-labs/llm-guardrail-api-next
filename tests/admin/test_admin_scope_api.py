from __future__ import annotations

from importlib import reload
from typing import Iterator

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def admin_client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("ADMIN_AUTH_MODE", "disabled")
    import app.config as app_config
    import app.main as app_main
    import app.security.rbac as app_rbac

    reload(app_config)
    reload(app_rbac)
    app_main = reload(app_main)
    app = app_main.create_app()
    with TestClient(app) as client:
        yield client


@pytest.mark.parametrize("path", ["/admin/api/scope/effective"])
def test_effective_scope_headers(admin_client: TestClient, path: str) -> None:
    response = admin_client.get(path)
    assert response.status_code == 200
    payload = response.json()
    assert isinstance(payload, dict)
    assert "X-Guardrail-Scope-Tenant" in response.headers
    assert "X-Guardrail-Scope-Bot" in response.headers


def test_bindings_requires_tenant_bot(admin_client: TestClient) -> None:
    response = admin_client.get("/admin/api/scope/bindings")
    assert response.status_code in (400, 422)


def test_secrets_requires_tenant_bot(admin_client: TestClient) -> None:
    response = admin_client.get("/admin/api/scope/secrets")
    assert response.status_code in (400, 422)


def test_bindings_ok_minimal(admin_client: TestClient) -> None:
    response = admin_client.get(
        "/admin/api/scope/bindings", params={"tenant": "acme", "bot": "sales"}
    )
    assert response.status_code in (200, 403)
    if response.status_code == 200:
        body = response.json()
        assert body["tenant"] == "acme"
        assert body["bot"] == "sales"
        assert "policy_packs" in body
        assert "mitigation_overrides" in body


def test_secrets_ok_minimal(admin_client: TestClient) -> None:
    response = admin_client.get(
        "/admin/api/scope/secrets", params={"tenant": "acme", "bot": "sales"}
    )
    assert response.status_code in (200, 403)
    if response.status_code == 200:
        body = response.json()
        assert "secret_sets" in body
        assert isinstance(body["secret_sets"], list)

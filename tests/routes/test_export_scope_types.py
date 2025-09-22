from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import config
from app.services import config as services_config
from app.main import create_app
from app.security import service_tokens as ST
from app.services import decisions_store as decisions_store


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _configure_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "export-secret"
    monkeypatch.setenv("SERVICE_TOKEN_SECRET", secret)
    monkeypatch.setattr(config, "SERVICE_TOKEN_SECRET", secret, raising=False)
    ST.reset_memory_store()
    monkeypatch.setattr(
        decisions_store,
        "_fetch_decisions_sorted_desc",
        lambda **_: [],
        raising=False,
    )


def _mint_token(*, tenants, bots, role: str = "admin") -> str:
    minted = ST.mint(role=role, tenants=tenants, bots=bots)
    return str(minted["token"])


@pytest.fixture
def client_flag_on(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("SCOPE_AUTOCONSTRAIN_ENABLED", "true")
    monkeypatch.setattr(
        services_config, "SCOPE_AUTOCONSTRAIN_ENABLED", True, raising=False
    )
    _configure_tokens(monkeypatch)
    app = create_app()
    return TestClient(app)


@pytest.fixture
def client_flag_off(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("SCOPE_AUTOCONSTRAIN_ENABLED", "false")
    monkeypatch.setattr(
        services_config, "SCOPE_AUTOCONSTRAIN_ENABLED", False, raising=False
    )
    _configure_tokens(monkeypatch)
    app = create_app()
    return TestClient(app)


def test_export_403_when_flag_off_and_missing_filters(
    client_flag_off: TestClient,
) -> None:
    token = _mint_token(tenants=["acme"], bots=["site"])
    response = client_flag_off.get(
        "/admin/api/decisions/export.ndjson",
        headers=_auth(token),
    )
    assert response.status_code == 403


def test_export_autoconstraint_single_scope_ok(client_flag_on: TestClient) -> None:
    token = _mint_token(tenants=["acme"], bots=["site"])
    with client_flag_on.stream(
        "GET",
        "/admin/api/decisions/export.ndjson",
        headers=_auth(token),
    ) as response:
        assert response.status_code == 200
        assert response.headers.get("X-Guardrail-Scope-Tenant") == "acme"


def test_export_autoconstraint_multi_scope_requires_explicit_filter(
    client_flag_on: TestClient,
) -> None:
    token = _mint_token(tenants=["acme", "beta"], bots=["site"])
    response = client_flag_on.get(
        "/admin/api/decisions/export.ndjson",
        headers=_auth(token),
    )
    assert response.status_code == 400
    assert "multiple tenant scopes" in response.text

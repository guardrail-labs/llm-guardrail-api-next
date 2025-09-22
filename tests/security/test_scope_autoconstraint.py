from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import config
from app.services import config as services_config
from app.main import create_app
from app.security import service_tokens as ST


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _configure_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "secret-key"
    monkeypatch.setenv("SERVICE_TOKEN_SECRET", secret)
    monkeypatch.setattr(config, "SERVICE_TOKEN_SECRET", secret, raising=False)
    ST.reset_memory_store()


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


def test_missing_filters_403_when_flag_off(client_flag_off: TestClient) -> None:
    token = _mint_token(tenants=["acme"], bots=["site"])
    response = client_flag_off.get("/admin/api/decisions", headers=_auth(token))
    assert response.status_code == 403


def test_missing_filters_autoconstrained_when_flag_on(client_flag_on: TestClient) -> None:
    token = _mint_token(tenants=["acme"], bots=["site"])
    response = client_flag_on.get("/admin/api/decisions", headers=_auth(token))
    assert response.status_code == 200
    assert response.headers.get("X-Guardrail-Scope-Tenant") == "acme"
    assert response.headers.get("X-Guardrail-Scope-Bot") == "site"


def test_conflicting_filter_rejected(client_flag_on: TestClient) -> None:
    token = _mint_token(tenants=["acme"], bots=["site"])
    response = client_flag_on.get(
        "/admin/api/decisions?tenant=other",
        headers=_auth(token),
    )
    assert response.status_code == 403

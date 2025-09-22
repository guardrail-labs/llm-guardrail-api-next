import importlib

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.security import service_tokens


def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _reload_config():
    import app.config as config_module

    importlib.reload(config_module)


def _mint_token(*, tenants: str, bots: str, role: str = "admin") -> str:
    minted = service_tokens.mint(role=role, tenants=tenants, bots=bots)
    return str(minted["token"])


@pytest.fixture
def client_flag_on(monkeypatch) -> TestClient:
    monkeypatch.setenv("SERVICE_TOKEN_SECRET", "secret")
    monkeypatch.setenv("SCOPE_AUTOCONSTRAIN_ENABLED", "true")
    _reload_config()
    app = create_app()
    return TestClient(app)


@pytest.fixture
def client_flag_off(monkeypatch) -> TestClient:
    monkeypatch.setenv("SERVICE_TOKEN_SECRET", "secret")
    monkeypatch.setenv("SCOPE_AUTOCONSTRAIN_ENABLED", "false")
    _reload_config()
    app = create_app()
    return TestClient(app)


def test_missing_filters_403_when_flag_off(client_flag_off):
    token = _mint_token(tenants="acme", bots="site")
    response = client_flag_off.get(
        "/admin/api/decisions", headers=_auth_header(token)
    )
    assert response.status_code == 403
    assert "filter" in response.text or "scope" in response.text


def test_missing_filters_autoconstrained_when_flag_on(client_flag_on):
    token = _mint_token(tenants="acme", bots="site")
    response = client_flag_on.get(
        "/admin/api/decisions", headers=_auth_header(token)
    )
    assert response.status_code == 200
    assert response.headers.get("X-Guardrail-Scope-Tenant") == "acme"
    assert response.headers.get("X-Guardrail-Scope-Bot") == "site"


def test_conflicting_filter_rejected(client_flag_on):
    token = _mint_token(tenants="acme", bots="site")
    response = client_flag_on.get(
        "/admin/api/decisions?tenant=other", headers=_auth_header(token)
    )
    assert response.status_code == 403
    assert "scope" in response.text.lower()

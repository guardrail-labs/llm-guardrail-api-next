import pytest
from fastapi.testclient import TestClient

from app import config
from app.main import create_app
from app.security import service_tokens as ST


def _configure_secret(monkeypatch) -> None:
    monkeypatch.setenv("SERVICE_TOKEN_SECRET", "s3cr3t")
    monkeypatch.setattr(config, "SERVICE_TOKEN_SECRET", "s3cr3t", raising=False)


def _client() -> TestClient:
    app = create_app()
    return TestClient(app)


def test_mint_and_verify_and_revoke(monkeypatch) -> None:
    _configure_secret(monkeypatch)
    ST.reset_memory_store()
    client = _client()
    assert client  # ensure app initializes

    minted = ST.mint(role="operator", tenants=["t1", "t2"], bots="*")
    token = minted["token"]
    claims = ST.verify(token)
    assert claims["role"] == "operator"
    assert "t1" in claims["tenants"]

    ST.revoke(claims["jti"])
    with pytest.raises(Exception):
        ST.verify(token)


def test_scope_enforced_on_admin_endpoint(monkeypatch) -> None:
    _configure_secret(monkeypatch)
    ST.reset_memory_store()
    token = ST.mint(role="viewer", tenants=["acme"], bots=["site"])["token"]

    client = _client()
    response = client.get(
        "/admin/api/decisions?tenant=other",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code in (401, 403)

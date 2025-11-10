from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

import pytest
from fastapi.testclient import TestClient

from app import config
from app.main import create_app
from app.security import service_tokens as ST
from app.services import config as services_config, decisions_store


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


def _normalize_scope(scope: Optional[Iterable[str] | str]) -> Optional[set[str]]:
    if scope is None:
        return None
    if isinstance(scope, str):
        return {scope}
    return {str(item) for item in scope}


@pytest.fixture
def seed_decisions_multi_tenant(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    base = datetime(2024, 1, 1, tzinfo=timezone.utc)
    samples: list[dict[str, Any]] = [
        {
            "id": "dec-acme",
            "ts": base + timedelta(seconds=3),
            "ts_ms": int((base + timedelta(seconds=3)).timestamp() * 1000),
            "tenant": "acme",
            "bot": "site",
            "outcome": "allow",
            "details": None,
        },
        {
            "id": "dec-beta",
            "ts": base + timedelta(seconds=2),
            "ts_ms": int((base + timedelta(seconds=2)).timestamp() * 1000),
            "tenant": "beta",
            "bot": "site",
            "outcome": "block",
            "details": None,
        },
        {
            "id": "dec-gamma",
            "ts": base + timedelta(seconds=1),
            "ts_ms": int((base + timedelta(seconds=1)).timestamp() * 1000),
            "tenant": "gamma",
            "bot": "site",
            "outcome": "allow",
            "details": None,
        },
        {
            "id": "dec-acme-agent",
            "ts": base,
            "ts_ms": int(base.timestamp() * 1000),
            "tenant": "acme",
            "bot": "agent",
            "outcome": "allow",
            "details": None,
        },
    ]

    def fake_fetch(
        *,
        tenant: Optional[Iterable[str] | str] = None,
        bot: Optional[Iterable[str] | str] = None,
        limit: int,
        cursor: Optional[tuple[int, str]],
        dir: str,
        since_ts_ms: Optional[int] = None,
        outcome: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> list[dict[str, object]]:
        tenant_scope = _normalize_scope(tenant)
        bot_scope = _normalize_scope(bot)
        filtered: list[dict[str, Any]] = []
        for item in samples:
            if tenant_scope is not None and item["tenant"] not in tenant_scope:
                continue
            if bot_scope is not None and item["bot"] not in bot_scope:
                continue
            filtered.append(dict(item))
        filtered.sort(
            key=lambda entry: (int(entry["ts_ms"]), str(entry["id"])),
            reverse=True,
        )
        max_items = max(int(limit), 0)
        if max_items:
            return filtered[:max_items]
        return filtered

    monkeypatch.setattr(
        decisions_store,
        "_fetch_decisions_sorted_desc",
        fake_fetch,
        raising=False,
    )
    return samples


@pytest.fixture
def client_flag_on(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("SCOPE_AUTOCONSTRAIN_ENABLED", "true")
    monkeypatch.setattr(services_config, "SCOPE_AUTOCONSTRAIN_ENABLED", True, raising=False)
    _configure_tokens(monkeypatch)
    app = create_app()
    return TestClient(app)


@pytest.fixture
def client_flag_off(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("SCOPE_AUTOCONSTRAIN_ENABLED", "false")
    monkeypatch.setattr(services_config, "SCOPE_AUTOCONSTRAIN_ENABLED", False, raising=False)
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


def test_multi_tenant_token_returns_union_when_flag_on(
    client_flag_on: TestClient,
    seed_decisions_multi_tenant: list[dict[str, object]],
) -> None:
    token = _mint_token(tenants=["acme", "beta"], bots=["site"], role="admin")
    response = client_flag_on.get(
        "/admin/api/decisions?limit=100",
        headers=_auth(token),
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["items"], "expected decisions for in-scope tenants"
    tenants = {item["tenant"] for item in payload["items"]}
    assert tenants == {"acme", "beta"}
    bots = {item["bot"] for item in payload["items"]}
    assert bots == {"site"}
    assert response.headers.get("X-Guardrail-Scope-Tenant") == "acme,beta"

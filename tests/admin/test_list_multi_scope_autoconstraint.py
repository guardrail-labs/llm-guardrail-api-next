from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import config
from app.main import create_app
from app.observability import adjudication_log
from app.security import service_tokens as ST
from app.services import config as services_config


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _configure_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "multi-scope-secret"
    monkeypatch.setenv("SERVICE_TOKEN_SECRET", secret)
    monkeypatch.setattr(config, "SERVICE_TOKEN_SECRET", secret, raising=False)
    ST.reset_memory_store()


@pytest.fixture
def client_flag_on(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("SCOPE_AUTOCONSTRAIN_ENABLED", "true")
    monkeypatch.setattr(
        services_config,
        "SCOPE_AUTOCONSTRAIN_ENABLED",
        True,
        raising=False,
    )
    _configure_tokens(monkeypatch)
    app = create_app()
    return TestClient(app)


@pytest.fixture
def seed_adjudications_multi_tenant(
) -> Iterator[list[adjudication_log.AdjudicationRecord]]:
    adjudication_log.clear()
    base = datetime(2024, 2, 1, tzinfo=timezone.utc)
    records = [
        adjudication_log.AdjudicationRecord(
            ts=(base + timedelta(seconds=3)).isoformat().replace("+00:00", "Z"),
            request_id="req-acme",
            tenant="acme",
            bot="site",
            provider="prov",
            decision="allow",
            rule_hits=[],
            score=None,
            latency_ms=10,
            policy_version=None,
            rules_path=None,
            sampled=False,
            prompt_sha256=None,
        ),
        adjudication_log.AdjudicationRecord(
            ts=(base + timedelta(seconds=2)).isoformat().replace("+00:00", "Z"),
            request_id="req-beta",
            tenant="beta",
            bot="agent",
            provider="prov",
            decision="block",
            rule_hits=[],
            score=None,
            latency_ms=12,
            policy_version=None,
            rules_path=None,
            sampled=False,
            prompt_sha256=None,
        ),
        adjudication_log.AdjudicationRecord(
            ts=(base + timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
            request_id="req-gamma",
            tenant="gamma",
            bot="site",
            provider="prov",
            decision="allow",
            rule_hits=[],
            score=None,
            latency_ms=15,
            policy_version=None,
            rules_path=None,
            sampled=False,
            prompt_sha256=None,
        ),
        adjudication_log.AdjudicationRecord(
            ts=base.isoformat().replace("+00:00", "Z"),
            request_id="req-acme-agent",
            tenant="acme",
            bot="agent",
            provider="prov",
            decision="allow",
            rule_hits=[],
            score=None,
            latency_ms=9,
            policy_version=None,
            rules_path=None,
            sampled=False,
            prompt_sha256=None,
        ),
    ]
    for record in records:
        adjudication_log.append(record)
    try:
        yield records
    finally:
        adjudication_log.clear()


def test_adjudications_multi_scope_union(
    client_flag_on: TestClient,
    seed_adjudications_multi_tenant: list[adjudication_log.AdjudicationRecord],
) -> None:
    token = ST.mint(
        role="admin",
        tenants=["acme", "beta"],
        bots=["site", "agent"],
    )["token"]
    response = client_flag_on.get(
        "/admin/api/adjudications?limit=100",
        headers=_auth(str(token)),
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["items"], "expected adjudication records in scope"
    tenants = {item["tenant"] for item in payload["items"]}
    assert tenants == {"acme", "beta"}
    bots = {item["bot"] for item in payload["items"]}
    assert bots == {"site", "agent"}
    assert response.headers.get("X-Guardrail-Scope-Tenant") == "acme,beta"
    assert response.headers.get("X-Guardrail-Scope-Bot") == "agent,site"

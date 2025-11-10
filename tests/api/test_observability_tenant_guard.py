from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Iterator

import pytest
from fastapi.testclient import TestClient

import app.observability.adjudication_log as adjudication_log
from app.security.rbac import require_viewer


def _ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _append_clarification(*, tenant: str, request_id: str) -> None:
    adjudication_log.append(
        adjudication_log.AdjudicationRecord(
            ts=_ts(datetime.now(timezone.utc)),
            request_id=request_id,
            tenant=tenant,
            bot="bot-1",
            provider="core",
            decision="clarify",
            rule_hits=[],
            score=None,
            latency_ms=12,
            policy_version="v1",
            rules_path="/policy/path",
            sampled=False,
            prompt_sha256=None,
        )
    )


@pytest.fixture(autouse=True)
def _reset_log() -> Iterator[None]:
    adjudication_log.clear()
    try:
        yield
    finally:
        adjudication_log.clear()


def _override_viewer(app, user: Dict[str, object]) -> None:
    app.dependency_overrides[require_viewer] = lambda: user


def _clear_override(app) -> None:
    app.dependency_overrides.pop(require_viewer, None)


def _scoped_viewer() -> Dict[str, object]:
    return {
        "email": "tenant-admin@example.com",
        "role": "admin",
        "scope": {"tenants": ["tenant-a"], "bots": "*"},
    }


def test_tenant_admin_can_access_own_data(client: TestClient) -> None:
    _append_clarification(tenant="tenant-a", request_id="req-own")
    app = client.app
    try:
        _override_viewer(app, _scoped_viewer())
        response = client.get("/observability/clarifications", params={"tenant": "tenant-a"})
    finally:
        _clear_override(app)

    assert response.status_code == 200
    body = response.json()
    assert body["items"], "expected clarifications for tenant"
    assert all(item["tenant"] == "tenant-a" for item in body["items"])


def test_cross_tenant_access_is_blocked(client: TestClient) -> None:
    _append_clarification(tenant="tenant-b", request_id="req-b")
    app = client.app
    try:
        _override_viewer(app, _scoped_viewer())
        response = client.get("/observability/clarifications", params={"tenant": "tenant-b"})
    finally:
        _clear_override(app)

    assert response.status_code == 403


def test_super_admin_can_access_any_tenant(client: TestClient) -> None:
    _append_clarification(tenant="tenant-b", request_id="req-b")
    app = client.app
    try:
        _override_viewer(
            app,
            {
                "email": "super@example.com",
                "role": "admin",
                "scope": {"tenants": "*", "bots": "*"},
            },
        )
        response = client.get("/observability/clarifications", params={"tenant": "tenant-b"})
    finally:
        _clear_override(app)

    assert response.status_code == 200
    body = response.json()
    assert body["items"], "expected clarifications for requested tenant"
    assert all(item["tenant"] == "tenant-b" for item in body["items"])


def test_unauthenticated_request_is_rejected(client: TestClient) -> None:
    _append_clarification(tenant="tenant-a", request_id="req-a")
    response = client.get("/observability/clarifications", params={"tenant": "tenant-a"})
    assert response.status_code in {401, 403}


def test_invalid_since_returns_400(client: TestClient) -> None:
    _append_clarification(tenant="tenant-a", request_id="req-invalid-since")
    app = client.app
    try:
        _override_viewer(app, _scoped_viewer())
        response = client.get(
            "/observability/clarifications",
            params={"tenant": "tenant-a", "since": 10**20},
        )
    finally:
        _clear_override(app)

    assert response.status_code == 400
    body = response.json()
    assert "detail" in body and body["detail"]


def test_invalid_cursor_returns_400(client: TestClient) -> None:
    _append_clarification(tenant="tenant-a", request_id="req-invalid-cursor")
    app = client.app
    try:
        _override_viewer(app, _scoped_viewer())
        response = client.get(
            "/observability/clarifications",
            params={"tenant": "tenant-a", "cursor": "not-a-valid-cursor"},
        )
    finally:
        _clear_override(app)

    assert response.status_code == 400
    body = response.json()
    assert "detail" in body and body["detail"]


def test_valid_request_returns_200(client: TestClient) -> None:
    _append_clarification(tenant="tenant-a", request_id="req-valid")
    app = client.app
    try:
        _override_viewer(app, _scoped_viewer())
        response = client.get(
            "/observability/clarifications",
            params={"tenant": "tenant-a", "since": 0},
        )
    finally:
        _clear_override(app)

    assert response.status_code == 200
    body = response.json()
    assert "items" in body
    assert body["items"], "expected clarifications for tenant"

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, List, cast

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from app.main import create_app
from app.observability import adjudication_log as AL
from app.routes import admin_retention as retention_route
from app.security import rbac
from app.services import retention as retention_service


def _ts(ms: int) -> str:
    return (
        datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def seed_adjudications(base: int, extra: List[AL.AdjudicationRecord] | None = None) -> None:
    AL.clear()
    AL.append(
        AL.AdjudicationRecord(
            ts=_ts(base - 10),
            request_id="oldA",
            tenant="t",
            bot="b",
            provider="p",
            decision="allow",
            rule_hits=[],
            score=None,
            latency_ms=0,
            policy_version=None,
            rules_path=None,
            sampled=False,
            prompt_sha256=None,
        )
    )
    AL.append(
        AL.AdjudicationRecord(
            ts=_ts(base + 10),
            request_id="newA",
            tenant="t",
            bot="b",
            provider="p",
            decision="allow",
            rule_hits=[],
            score=None,
            latency_ms=0,
            policy_version=None,
            rules_path=None,
            sampled=False,
            prompt_sha256=None,
        )
    )
    for record in extra or []:
        AL.append(record)


@pytest.fixture()
def app_factory(monkeypatch: pytest.MonkeyPatch) -> Callable[[], FastAPI]:
    monkeypatch.setattr(retention_route, "require_csrf", lambda request: None)
    monkeypatch.setattr(retention_service, "_decisions_supports_sql", lambda: False)

    def factory() -> FastAPI:
        app = create_app()

        def _allow(_: Request) -> None:
            return None

        app.dependency_overrides[rbac.require_viewer] = _allow
        app.dependency_overrides[rbac.require_operator] = _allow
        return app

    return factory


def test_preview_counts(app_factory: Callable[[], object], monkeypatch: pytest.MonkeyPatch):
    base = 1_700_000_000_000
    monkeypatch.setattr(retention_service, "_decisions_supports_sql", lambda: False)
    from app.services import decisions_store as store

    items = [
        {"id": "x", "ts_ms": base - 5, "tenant": "t", "bot": "b"},
        {"id": "y", "ts_ms": base + 5, "tenant": "t", "bot": "b"},
    ]
    monkeypatch.setattr(store, "_fetch_decisions_sorted_desc", lambda **_: list(items))

    seed_adjudications(base)

    app = app_factory()
    client = TestClient(cast(Any, app))
    resp = client.post(
        "/admin/api/retention/preview",
        json={"before_ts_ms": base, "tenant": "t", "bot": "b"},
    )
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["decisions"]["count"] == 1
    assert payload["adjudications"]["count"] == 1


def test_execute_deletes_with_confirmation_and_csrf(
    app_factory: Callable[[], object],
    monkeypatch: pytest.MonkeyPatch,
):
    base = 1_700_000_000_000
    monkeypatch.setattr(retention_service, "_decisions_supports_sql", lambda: False)
    from app.services import decisions_store as store

    decisions: List[dict[str, object]] = [
        {"id": "x", "ts_ms": base - 5, "tenant": "t", "bot": "b"},
        {"id": "y", "ts_ms": base + 5, "tenant": "t", "bot": "b"},
    ]

    monkeypatch.setattr(store, "_fetch_decisions_sorted_desc", lambda **_: list(decisions))

    def _assign(items):
        decisions[:] = list(items)

    monkeypatch.setattr(store, "_set_decisions_for_tests", _assign, raising=False)

    seed_adjudications(base)

    app = app_factory()
    client = TestClient(cast(Any, app))

    missing_confirm = client.post(
        "/admin/api/retention/execute",
        json={
            "before_ts_ms": base,
            "tenant": "t",
            "bot": "b",
            "csrf_token": "ok",
            "confirm": "nope",
        },
    )
    assert missing_confirm.status_code == 400

    missing_csrf = client.post(
        "/admin/api/retention/execute",
        json={"before_ts_ms": base, "tenant": "t", "bot": "b", "confirm": "DELETE"},
    )
    assert missing_csrf.status_code == 400

    good = client.post(
        "/admin/api/retention/execute",
        json={
            "before_ts_ms": base,
            "tenant": "t",
            "bot": "b",
            "csrf_token": "ok",
            "confirm": "DELETE",
        },
    )
    assert good.status_code == 200
    payload = good.json()
    assert payload["deleted"]["decisions"] == 1
    assert payload["deleted"]["adjudications"] == 1
    assert len(decisions) == 1 and decisions[0]["id"] == "y"
    assert all(rec.request_id != "oldA" for rec in AL.paged_query(limit=10, sort="ts_desc")[0])


def test_execute_respects_filters_and_batch_limit(
    app_factory: Callable[[], object], monkeypatch: pytest.MonkeyPatch
):
    base = 1_700_000_000_000
    monkeypatch.setattr(retention_service, "_decisions_supports_sql", lambda: False)
    from app.services import decisions_store as store

    decisions: List[dict[str, object]] = [
        {"id": "x", "ts_ms": base - 20, "tenant": "t", "bot": "b"},
        {"id": "y", "ts_ms": base - 15, "tenant": "t", "bot": "b"},
        {"id": "z", "ts_ms": base - 5, "tenant": "t", "bot": "other"},
    ]
    monkeypatch.setattr(store, "_fetch_decisions_sorted_desc", lambda **_: list(decisions))

    def _assign(items):
        decisions[:] = list(items)

    monkeypatch.setattr(store, "_set_decisions_for_tests", _assign, raising=False)

    extra_records = [
        AL.AdjudicationRecord(
            ts=_ts(base - 20),
            request_id="oldB",
            tenant="t",
            bot="b",
            provider="p",
            decision="allow",
            rule_hits=[],
            score=None,
            latency_ms=0,
            policy_version=None,
            rules_path=None,
            sampled=False,
            prompt_sha256=None,
        ),
        AL.AdjudicationRecord(
            ts=_ts(base - 5),
            request_id="oldC",
            tenant="t",
            bot="other",
            provider="p",
            decision="allow",
            rule_hits=[],
            score=None,
            latency_ms=0,
            policy_version=None,
            rules_path=None,
            sampled=False,
            prompt_sha256=None,
        ),
    ]
    seed_adjudications(base, extra_records)

    app = app_factory()
    client = TestClient(cast(Any, app))
    resp = client.post(
        "/admin/api/retention/execute",
        json={
            "before_ts_ms": base - 1,
            "tenant": "t",
            "bot": "b",
            "csrf_token": "ok",
            "confirm": "DELETE",
            "max_delete": 2,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["deleted"]["decisions"] == 2
    assert data["deleted"]["adjudications"] == 0
    assert all(
        entry["bot"] != "b" or cast(int, entry["ts_ms"]) >= base - 1
        for entry in decisions
    )


def test_auth_and_csrf_enforced(monkeypatch: pytest.MonkeyPatch):
    def fail_admin(_: Request) -> None:
        raise HTTPException(status_code=403, detail="forbidden")

    from app.routes import admin_mitigation
    from app.services import decisions_store as store

    app = create_app()
    app.dependency_overrides[rbac.require_viewer] = fail_admin
    client = TestClient(cast(Any, app))
    resp = client.post("/admin/api/retention/preview", json={"before_ts_ms": 1})
    assert resp.status_code == 403

    def _csrf_fail(request: Request) -> None:
        raise HTTPException(status_code=400, detail="csrf")

    monkeypatch.setattr(retention_service, "_decisions_supports_sql", lambda: False)
    monkeypatch.setattr(
        store, "_fetch_decisions_sorted_desc", lambda **_: [], raising=False
    )
    app2 = create_app()
    app2.dependency_overrides[rbac.require_viewer] = lambda request: None
    app2.dependency_overrides[rbac.require_operator] = lambda request: None
    app2.dependency_overrides[admin_mitigation.require_csrf] = _csrf_fail
    client2 = TestClient(cast(Any, app2))
    resp2 = client2.post(
        "/admin/api/retention/execute",
        json={"before_ts_ms": 1, "confirm": "DELETE", "csrf_token": "ok"},
    )
    assert resp2.status_code == 400


def test_max_delete_cap_validation(app_factory: Callable[[], object]):
    app = app_factory()
    client = TestClient(cast(Any, app))
    resp = client.post(
        "/admin/api/retention/execute",
        json={
            "before_ts_ms": 1,
            "confirm": "DELETE",
            "csrf_token": "ok",
            "max_delete": 50_001,
        },
    )
    assert resp.status_code == 422

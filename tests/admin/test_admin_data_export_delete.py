from __future__ import annotations

import importlib
import json
import time
from datetime import datetime, timezone
from typing import Any, Callable, Tuple

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from app.main import create_app
from app.observability import adjudication_log as adj_log
from app.routes.admin_mitigation import require_csrf
from app.security import rbac
from app.services import decisions_bus


def _iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).isoformat().replace("+00:00", "Z")


@pytest.fixture()
def prepare_audit(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AUDIT_BACKEND", "memory")
    monkeypatch.delenv("AUDIT_LOG_FILE", raising=False)
    from app import config as app_config

    importlib.reload(app_config)
    from app.observability import admin_audit as audit_log

    audit_module = importlib.reload(audit_log)
    from app.routes import admin_data_lifecycle as lifecycle_route

    importlib.reload(lifecycle_route)
    return audit_module


@pytest.fixture()
def app_builder(prepare_audit) -> Callable[[bool, bool], Tuple[TestClient, Any]]:
    audit_module: Any = prepare_audit

    def builder(
        require_admin_override: bool, require_csrf_override: bool
    ) -> Tuple[TestClient, Any]:
        app = create_app()
        if require_admin_override:
            app.dependency_overrides[rbac.require_admin] = lambda: {
                "email": "admin@test",
                "role": "admin",
            }
        if require_csrf_override:

            def _noop_csrf(_: Request) -> None:
                return None

            app.dependency_overrides[require_csrf] = _noop_csrf
        client = TestClient(app)
        return client, audit_module

    return builder


def _seed_data(audit_module: Any, base_ms: int) -> None:
    decisions_bus.configure(reset=True)
    decisions_bus.publish({"ts_ms": base_ms - 5000, "tenant": "t", "bot": "b", "request_id": "d1"})
    decisions_bus.publish(
        {"ts_ms": base_ms + 5000, "tenant": "t", "bot": "other", "request_id": "d2"}
    )

    adj_log.clear()
    adj_log.append(
        adj_log.AdjudicationRecord(
            ts=_iso(base_ms - 4000),
            request_id="a1",
            tenant="t",
            bot="b",
            provider="p",
            decision="allow",
            rule_hits=[],
            score=None,
            latency_ms=1,
            policy_version=None,
            rules_path=None,
            sampled=False,
            prompt_sha256=None,
        )
    )
    adj_log.append(
        adj_log.AdjudicationRecord(
            ts=_iso(base_ms + 1000),
            request_id="a2",
            tenant="t",
            bot="other",
            provider="p",
            decision="allow",
            rule_hits=[],
            score=None,
            latency_ms=1,
            policy_version=None,
            rules_path=None,
            sampled=False,
            prompt_sha256=None,
        )
    )

    with audit_module._LOG_LOCK:  # pylint: disable=protected-access
        audit_module._RING.clear()
    audit_module.record(
        action="seed_event",
        actor_email="seed@test",
        actor_role="admin",
        tenant="t",
        bot="b",
        outcome="ok",
        meta={},
    )


def test_export_filters_and_audit(app_builder):
    base = int(time.time() * 1000)
    client, audit_module = app_builder(True, True)
    _seed_data(audit_module, base)

    response = client.get(
        "/admin/api/data/export.ndjson",
        params={
            "kinds": "decisions,adjudications,audit",
            "tenant": "t",
            "bot": "b",
            "since": base - 10_000,
            "until": base + 1_000,
        },
    )

    assert response.status_code == 200
    payloads = [json.loads(line) for line in response.text.splitlines() if line.strip()]
    kinds = {item["kind"] for item in payloads}
    assert kinds == {"decisions", "adjudications", "audit"}
    for item in payloads:
        assert item.get("tenant") == "t"
        assert item.get("bot") == "b"

    export_events = [evt for evt in audit_module.iter_events(action="data_export")]
    assert export_events
    last = export_events[-1]
    counts = last.get("meta", {}).get("counts", {})
    assert counts.get("decisions") == 1
    assert counts.get("adjudications") == 1
    assert counts.get("audit") >= 1


def test_delete_removes_records_and_audit(app_builder):
    base = int(time.time() * 1000)
    cutoff = base + 10_000
    client, audit_module = app_builder(True, True)
    _seed_data(audit_module, base)

    response = client.post(
        "/admin/api/data/delete",
        headers={"X-CSRF-Token": "token"},
        json={
            "kinds": ["decisions", "adjudications", "audit"],
            "tenant": "t",
            "bot": "b",
            "before_ts_ms": cutoff,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    counts = payload["deleted"]
    assert counts["decisions"] == 1
    assert counts["adjudications"] == 1
    assert counts["audit"] >= 1
    remaining_decisions = decisions_bus.snapshot()
    assert all(
        item.get("tenant") != "t" or item.get("bot") != "b" or item.get("ts_ms", 0) >= base
        for item in remaining_decisions
    )
    remaining_adj = list(adj_log.iter_all())
    assert all(item.get("request_id") != "a1" for item in remaining_adj)

    delete_events = [evt for evt in audit_module.iter_events(action="data_delete")]
    assert delete_events
    last = delete_events[-1]
    assert last.get("outcome") == "ok"
    assert last.get("meta", {}).get("counts", {}).get("decisions") == 1


def test_delete_requires_csrf_and_admin(app_builder):
    # Missing admin session
    unauth_client, _ = app_builder(False, True)
    resp = unauth_client.get("/admin/api/data/export.ndjson", params={"kinds": "decisions"})
    assert resp.status_code in {401, 403}

    # Missing CSRF token
    client, audit_module = app_builder(True, True)
    with audit_module._LOG_LOCK:  # pylint: disable=protected-access
        audit_module._RING.clear()
    resp2 = client.post(
        "/admin/api/data/delete",
        json={
            "kinds": ["decisions"],
            "before_ts_ms": int(time.time() * 1000) + 10_000,
        },
    )
    assert resp2.status_code == 400
    assert resp2.json()["detail"] == "CSRF token required"
    events = [evt for evt in audit_module.iter_events(action="data_delete")]
    assert events
    assert events[-1].get("outcome") == "error"
    assert events[-1].get("meta", {}).get("reason") == "csrf_required"

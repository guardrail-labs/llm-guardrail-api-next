from __future__ import annotations

from typing import Any, Dict

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from app.observability import admin_audit as AA


@pytest.fixture()
def _patched_dlq(monkeypatch: pytest.MonkeyPatch):
    import app.routes.admin_webhooks_dlq as dlq_route

    class _Stub:
        @staticmethod
        def purge_all() -> int:
            return 0

        @staticmethod
        def retry_all() -> int:
            return 0

        @staticmethod
        def stats() -> Dict[str, Any]:
            return {
                "size": 0,
                "oldest_ts_ms": None,
                "newest_ts_ms": None,
                "last_error": None,
            }

    monkeypatch.setattr(dlq_route, "DLQ", _Stub())
    monkeypatch.setattr(dlq_route, "_require_ui_csrf", lambda request, token: None)


@pytest.fixture()
def app_factory(_patched_dlq):
    from app.main import create_app
    from app.security import rbac as rbac_mod

    def factory():
        app = create_app()
        app.state.test_user = {"email": "test@example.com", "role": "operator"}

        def _allow(_: Request) -> Dict[str, Any]:
            user = getattr(app.state, "test_user", None)
            if isinstance(user, dict):
                return user
            return {"email": "test@example.com", "role": "operator"}

        app.dependency_overrides[rbac_mod.require_viewer] = _allow
        app.dependency_overrides[rbac_mod.require_operator] = _allow
        return app

    return factory


def _client(app_factory):
    return TestClient(app_factory())


def test_audit_records_and_recent_feed(app_factory, monkeypatch):
    monkeypatch.setenv("ADMIN_AUTH_MODE", "cookie")
    from app.security import rbac

    monkeypatch.setattr(
        rbac,
        "get_current_user",
        lambda _req: {"email": "u@ex", "role": "operator"},
        raising=True,
    )

    client = _client(app_factory)
    client.app.state.test_user = {"email": "u@ex", "role": "operator"}
    r = client.post("/admin/api/webhooks/dlq/purge", json={"csrf_token": "ok"})
    assert r.status_code == 200

    feed = client.get("/admin/api/audit/recent?limit=5")
    assert feed.status_code == 200
    items = feed.json()
    assert any(it["action"] == "dlq_purge" and it["actor_email"] == "u@ex" for it in items)


def test_audit_metrics_increment_on_error(app_factory, monkeypatch):
    monkeypatch.setenv("ADMIN_AUTH_MODE", "cookie")
    from app.security import rbac

    monkeypatch.setattr(
        rbac,
        "get_current_user",
        lambda _req: {"email": "ops@ex", "role": "operator"},
        raising=True,
    )

    from app.services import retention as retention_service

    monkeypatch.setattr(
        retention_service,
        "delete_decisions_before",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    client = _client(app_factory)
    client.app.state.test_user = {"email": "ops@ex", "role": "operator"}
    res = client.post(
        "/admin/api/retention/execute",
        json={"before_ts_ms": 1700000000000, "confirm": "DELETE", "csrf_token": "ok"},
    )
    assert res.status_code == 500

    recent = AA.recent(10)
    assert any(it["action"] == "retention_execute" and it["outcome"] == "error" for it in recent)


def test_recent_limit_clamps():
    base = len(AA.recent(500))
    for idx in range(10):
        AA.record(
            action="test_action",
            actor_email=f"user{idx}@ex",
            actor_role="operator",
            meta={"idx": idx},
        )
    subset = AA.recent(5)
    assert len(subset) == 5
    assert subset[-1]["meta"].get("idx") == 9
    assert len(AA.recent(500)) >= base

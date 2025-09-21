from __future__ import annotations

import json
from typing import Any, Callable, Dict, Iterator, Optional

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from app import config as app_config
from app.observability import admin_audit as AA


@pytest.fixture(autouse=True)
def reset_audit_state(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(app_config, "AUDIT_BACKEND", "", raising=False)
    monkeypatch.setattr(app_config, "AUDIT_LOG_FILE", "", raising=False)
    monkeypatch.setattr(app_config, "AUDIT_REDIS_KEY", "guardrail:admin_audit:v1", raising=False)
    monkeypatch.setattr(app_config, "AUDIT_REDIS_MAXLEN", 50000, raising=False)
    monkeypatch.setattr(app_config, "AUDIT_RECENT_LIMIT", 500, raising=False)
    monkeypatch.setattr(AA, "_REDIS_CLIENT", None, raising=False)
    monkeypatch.setattr(AA, "_REDIS_URL", None, raising=False)
    with AA._LOG_LOCK:
        AA._RING.clear()
    yield
    with AA._LOG_LOCK:
        AA._RING.clear()


@pytest.fixture()
def app_factory() -> Callable[[], Any]:
    from app.main import create_app
    from app.security import rbac as rbac_mod

    def _factory() -> Any:
        app = create_app()

        def _allow(_: Optional[Request] = None) -> Dict[str, Any]:
            return {"email": "admin@example.com", "role": "admin"}

        app.dependency_overrides[rbac_mod.require_viewer] = _allow
        return app

    return _factory


def test_export_falls_back_to_ring_when_file_backend_has_no_path(
    app_factory: Callable[[], Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AUDIT_BACKEND", "file")
    monkeypatch.delenv("AUDIT_LOG_FILE", raising=False)

    app = app_factory()
    AA.record(
        action="dlq_purge",
        actor_email="ops@x",
        actor_role="operator",
        outcome="ok",
        meta={"deleted": 2},
    )
    AA.record(
        action="mitigation_set",
        actor_email="admin@x",
        actor_role="admin",
        tenant="t",
        bot="b",
        outcome="ok",
        meta={"mode": "block"},
    )

    client = TestClient(app)
    response = client.get("/admin/api/audit/export.ndjson")
    assert response.status_code == 200

    lines = [json.loads(line) for line in response.text.splitlines() if line.strip()]
    actions = {item.get("action") for item in lines}

    assert "dlq_purge" in actions
    assert "mitigation_set" in actions

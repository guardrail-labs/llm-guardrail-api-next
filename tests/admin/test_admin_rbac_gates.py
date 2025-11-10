from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.routes.admin_ui import _csrf_token
from app.security import rbac
from app.services import retention as retention_service
from app.services import webhooks_dlq as dlq_service


@pytest.fixture()
def app_factory(monkeypatch):
    monkeypatch.setattr(retention_service, "_decisions_supports_sql", lambda: False)
    monkeypatch.setattr(retention_service, "count_decisions_before", lambda *a, **k: 0)
    monkeypatch.setattr(retention_service, "count_adjudications_before", lambda *a, **k: 0)
    monkeypatch.setattr(retention_service, "delete_decisions_before", lambda *a, **k: 1)
    monkeypatch.setattr(retention_service, "delete_adjudications_before", lambda *a, **k: 1)
    monkeypatch.setattr(
        dlq_service,
        "stats",
        lambda: {
            "size": 0,
            "oldest_ts_ms": None,
            "newest_ts_ms": None,
            "last_error": None,
        },
    )
    monkeypatch.setattr(dlq_service, "retry_all", lambda: 1)
    monkeypatch.setattr(dlq_service, "purge_all", lambda: 1)

    def factory():
        return create_app()

    return factory


def _as_role(monkeypatch, role: str) -> None:
    monkeypatch.setenv("ADMIN_AUTH_MODE", "cookie")
    monkeypatch.setenv("ADMIN_RBAC_DEFAULT_ROLE", "viewer")

    def fake_user(_request):
        return {"email": "t@example.com", "name": "T", "role": role}

    monkeypatch.setattr(rbac, "get_current_user", fake_user, raising=True)


def test_viewer_can_read_dlq_but_not_purge(app_factory, monkeypatch) -> None:
    _as_role(monkeypatch, "viewer")
    client = TestClient(app_factory())
    response = client.get("/admin/api/webhooks/dlq")
    assert response.status_code == 200
    response2 = client.post("/admin/api/webhooks/dlq/purge", json={"csrf_token": "ok"})
    assert response2.status_code in (401, 403)


def test_operator_can_purge_and_retention_execute(app_factory, monkeypatch) -> None:
    _as_role(monkeypatch, "operator")
    client = TestClient(app_factory())
    token = _csrf_token()
    client.cookies.set("ui_csrf", token)
    purge = client.post(
        "/admin/api/webhooks/dlq/purge",
        json={"csrf_token": token},
        headers={"X-CSRF-Token": token},
    )
    assert purge.status_code in (200, 204)
    preview = client.post(
        "/admin/api/retention/preview",
        json={"before_ts_ms": 1_700_000_000_000},
    )
    assert preview.status_code == 200
    execute = client.post(
        "/admin/api/retention/execute",
        json={
            "before_ts_ms": 1_700_000_000_000,
            "confirm": "DELETE",
            "csrf_token": token,
        },
        headers={"X-CSRF-Token": token},
    )
    assert execute.status_code == 200


def test_me_endpoint_reports_role(app_factory, monkeypatch) -> None:
    _as_role(monkeypatch, "admin")
    client = TestClient(app_factory())
    response = client.get("/admin/api/me")
    assert response.status_code == 200
    payload = response.json()
    assert payload["authenticated"] is True
    assert payload["role"] == "admin"

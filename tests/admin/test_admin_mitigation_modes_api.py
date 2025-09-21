from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.routes.admin_ui import _csrf_token
from app.services.mitigation_store import reset_for_tests


@pytest.fixture()
def app_factory():
    def _factory():
        reset_for_tests()
        return create_app()

    return _factory


def test_get_then_put_roundtrip(app_factory):
    app = app_factory()
    c = TestClient(app)
    token = _csrf_token()
    c.cookies.set("ui_csrf", token)

    r0 = c.get("/admin/api/mitigation-mode", params={"tenant": "t", "bot": "b"})
    assert r0.status_code == 200
    assert r0.json()["mode"] in (None, "block", "clarify", "redact")

    r1 = c.put(
        "/admin/api/mitigation-mode",
        json={"tenant": "t", "bot": "b", "mode": "block", "csrf_token": token},
        headers={"X-CSRF-Token": token},
    )
    assert r1.status_code == 200 and r1.json()["ok"] is True

    r2 = c.get("/admin/api/mitigation-mode", params={"tenant": "t", "bot": "b"})
    assert r2.status_code == 200
    assert r2.json()["mode"] == "block"


def test_bad_mode_400(app_factory):
    app = app_factory()
    c = TestClient(app)
    token = _csrf_token()
    c.cookies.set("ui_csrf", token)
    r = c.put(
        "/admin/api/mitigation-mode",
        json={"tenant": "t", "bot": "b", "mode": "nope", "csrf_token": token},
        headers={"X-CSRF-Token": token},
    )
    assert r.status_code == 400

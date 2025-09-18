from __future__ import annotations

import sys
import types

from fastapi import FastAPI
from fastapi.testclient import TestClient


def _app() -> FastAPI:
    app = FastAPI()
    from app.routes.admin_webhooks import router as r

    app.include_router(r)
    return app


def test_double_submit_cookie_required(monkeypatch):
    fake = types.SimpleNamespace(
        replay_dlq=lambda **kw: 3,
        dlq_size=lambda: 1,
        breaker_snapshot=lambda: {},
    )
    monkeypatch.setitem(sys.modules, "app.services.webhooks", fake)
    monkeypatch.setenv("ADMIN_CSRF_GUARD", "fake:guard")
    monkeypatch.setitem(
        sys.modules,
        "app.security.admin_auth",
        types.ModuleType("fake_admin_auth"),
    )

    app = _app()
    client = TestClient(app, base_url="https://testserver")

    resp_status = client.get("/admin/api/webhooks/status")
    assert resp_status.status_code == 200

    csrf_cookie = client.cookies.get("admin_csrf")
    assert csrf_cookie is not None

    resp_ok = client.post(
        "/admin/api/webhooks/replay",
        data={"max_batch": 5, "csrf": csrf_cookie},
    )
    assert resp_ok.status_code == 200
    assert resp_ok.json()["replayed"] == 3

    resp_bad = client.post(
        "/admin/api/webhooks/replay",
        data={"max_batch": 5, "csrf": "wrong"},
    )
    assert resp_bad.status_code == 400

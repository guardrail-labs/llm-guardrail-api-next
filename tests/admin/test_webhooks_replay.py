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


def test_replay_requires_csrf(monkeypatch) -> None:
    fake = types.ModuleType("fake_webhooks_replay")
    setattr(fake, "replay_dlq", lambda **_: 0)
    monkeypatch.setitem(sys.modules, "app.services.webhooks", fake)
    monkeypatch.setenv("ADMIN_CSRF_GUARD", "fake:guard")
    monkeypatch.setitem(
        sys.modules,
        "app.security.admin_auth",
        types.ModuleType("fake_admin_auth"),
    )
    app = _app()
    client = TestClient(app, base_url="https://testserver")
    resp = client.post("/admin/api/webhooks/replay", data={"max_batch": "10"})
    assert resp.status_code in (400, 401, 403)


def test_replay_limits_and_cooldown(monkeypatch) -> None:
    calls = {"n": 0}

    def replay_dlq(max_batch: int, since_seconds: int | None = None) -> int:
        del since_seconds
        calls["n"] += 1
        return min(max_batch, 5)

    fake = types.ModuleType("fake_webhooks_replay")
    setattr(fake, "replay_dlq", replay_dlq)
    setattr(fake, "dlq_peek", lambda n: [{"id": "y"}])
    monkeypatch.setitem(sys.modules, "app.services.webhooks", fake)
    monkeypatch.setenv("ADMIN_CSRF_GUARD", "fake:guard")
    monkeypatch.setitem(
        sys.modules,
        "app.security.admin_auth",
        types.ModuleType("fake_admin_auth"),
    )

    monkeypatch.setenv("WEBHOOK_REPLAY_MAX_BATCH", "100")
    monkeypatch.setenv("WEBHOOK_REPLAY_COOLDOWN_SEC", "2")

    app = _app()
    client = TestClient(app, base_url="https://testserver")
    monkeypatch.setattr("app.routes.admin_webhooks._LAST_REPLAY_AT", 0.0, raising=False)
    status = client.get("/admin/api/webhooks/status")
    assert status.status_code == 200
    token = client.cookies.get("admin_csrf")
    assert token

    ok = client.post("/admin/api/webhooks/replay", data={"max_batch": "10", "csrf": token})
    assert ok.status_code == 200
    again = client.post("/admin/api/webhooks/replay", data={"max_batch": "10", "csrf": token})
    assert again.status_code == 429
    assert calls["n"] == 1

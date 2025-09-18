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


def test_status_ok(monkeypatch) -> None:
    fake = types.ModuleType("fake_webhooks")
    setattr(fake, "dlq_size", lambda: 3)
    setattr(
        fake,
        "breaker_snapshot",
        lambda: {
            "api.example.com": {
                "state": "closed",
                "failures": 0,
                "opened_at": None,
            }
        },
    )
    setattr(fake, "dlq_peek", lambda n: [{"id": "x"}])
    monkeypatch.setitem(sys.modules, "app.services.webhooks", fake)

    app = _app()
    client = TestClient(app)
    resp = client.get("/admin/api/webhooks/status?peek=2")
    assert resp.status_code == 200
    data = resp.json()
    assert data["dlq"]["length"] == 3
    assert "api.example.com" in data["breaker"]

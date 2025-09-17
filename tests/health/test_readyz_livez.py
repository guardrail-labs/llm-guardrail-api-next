from __future__ import annotations

import sys
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient


def _app() -> FastAPI:
    app = FastAPI()
    from app.routes.health import router as health_router

    app.include_router(health_router)
    return app


def test_livez_ok() -> None:
    client = TestClient(_app())
    response = client.get("/livez")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_readyz_ok_without_deps(monkeypatch) -> None:
    client = TestClient(_app())
    response = client.get("/readyz")
    assert response.status_code in (200, 503)
    payload = response.json()
    assert "checks" in payload


def test_webhook_dlq_threshold_trips(monkeypatch) -> None:
    fake_service = SimpleNamespace(dlq_size=lambda: 5)
    monkeypatch.setitem(sys.modules, "app.services.webhooks", fake_service)
    try:
        client = TestClient(_app())
        response = client.get("/readyz")
        assert response.status_code == 503
        assert response.json()["checks"]["webhooks"]["status"] == "fail"
    finally:
        monkeypatch.delitem(sys.modules, "app.services.webhooks", raising=False)

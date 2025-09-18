from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.services import decisions as store


def _app():
    app = FastAPI()
    from app.routes.admin_decisions_api import router as r

    app.include_router(r)
    return app


def test_admin_api_reads_from_store(tmp_path, monkeypatch):
    dsn = f"sqlite:///{tmp_path}/decisions.db"
    monkeypatch.setenv("DECISIONS_DSN", dsn)
    import importlib

    importlib.reload(store)

    store.record(id="x1", ts=datetime.now(timezone.utc), tenant="acme", bot="ui", outcome="allow")

    app = _app()
    client = TestClient(app)
    response = client.get("/admin/api/decisions", params={"tenant": "acme"})
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1
    assert data["items"][0]["tenant"] == "acme"

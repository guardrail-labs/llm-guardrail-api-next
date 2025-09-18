from __future__ import annotations

import sys
import types
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient


def _app() -> FastAPI:
    app = FastAPI()
    from app.routes.admin_decisions_export import router as export_router

    app.include_router(export_router)
    return app


def _install_fake_store(monkeypatch):
    now = datetime.now(timezone.utc)
    rows = [
        {
            "id": "a1",
            "ts": now - timedelta(minutes=2),
            "tenant": "t1",
            "bot": "b1",
            "outcome": "allow",
            "details": {"k": 1},
        },
        {
            "id": "a2",
            "ts": now - timedelta(minutes=1),
            "tenant": "t1",
            "bot": "b2",
            "outcome": "block_input_only",
            "rule_id": "r1",
        },
        {
            "id": "a3",
            "ts": now,
            "tenant": "t2",
            "bot": "b1",
            "outcome": "redact",
            "details": {"r": ["x"]},
        },
    ]

    def query(since, tenant, bot, outcome, limit, offset):
        def ok(row):
            if since and row["ts"] < since:
                return False
            if tenant and row["tenant"] != tenant:
                return False
            if bot and row["bot"] != bot:
                return False
            if outcome and row["outcome"] != outcome:
                return False
            return True

        sel = [r for r in rows if ok(r)]
        page = sel[offset : offset + limit]
        return page, len(sel)

    fake_store = types.ModuleType("app.services.decisions")
    setattr(fake_store, "query", query)
    monkeypatch.setitem(sys.modules, "app.services.decisions", fake_store)
    fake_guard = types.ModuleType("app.routes.admin_rbac")
    setattr(fake_guard, "require_admin", lambda request: None)
    monkeypatch.setitem(sys.modules, "app.routes.admin_rbac", fake_guard)
    from app.routes import admin_decisions_api as decisions_api

    monkeypatch.setattr(decisions_api, "_provider", query, raising=False)


def test_export_csv_streams(monkeypatch):
    _install_fake_store(monkeypatch)
    app = _app()
    client = TestClient(app)

    response = client.get("/admin/api/decisions/export.csv")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    first_line = response.text.splitlines()[0]
    assert first_line.startswith("id,ts,tenant,bot,outcome")


def test_export_ndjson_streams(monkeypatch):
    _install_fake_store(monkeypatch)
    app = _app()
    client = TestClient(app)

    response = client.get("/admin/api/decisions/export.ndjson")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-ndjson")
    lines = [ln for ln in response.text.splitlines() if ln.strip()]
    assert lines and lines[0].startswith("{")

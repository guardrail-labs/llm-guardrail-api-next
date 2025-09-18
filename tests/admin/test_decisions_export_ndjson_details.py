import csv
import json
import sys
import types
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.routes import admin_decisions_api


@pytest.fixture(autouse=True)
def reset_decision_provider():
    previous_provider = getattr(admin_decisions_api, "_provider", None)
    existing_module = sys.modules.get("app.services.decisions")
    try:
        yield
    finally:
        admin_decisions_api._provider = previous_provider
        if existing_module is not None:
            sys.modules["app.services.decisions"] = existing_module
        else:
            sys.modules.pop("app.services.decisions", None)


def _app() -> FastAPI:
    app = FastAPI()
    from app.routes.admin_decisions_export import router as r

    app.include_router(r)
    return app


def _install_fake_store(obj_details: bool = True) -> None:
    now = datetime.now(timezone.utc)
    details = {"foo": "bar"} if obj_details else '{"foo":"bar"}'
    rows = [
        {
            "id": "x1",
            "ts": now,
            "tenant": "t",
            "bot": "b",
            "outcome": "allow",
            "details": details,
        }
    ]

    def query(since, tenant, bot, outcome, limit, offset):
        return rows[offset : offset + limit], len(rows)

    module = types.ModuleType("app.services.decisions")
    module.query = query  # type: ignore[attr-defined]
    sys.modules["app.services.decisions"] = module

    def provider(since, tenant, bot, outcome, limit, offset):
        return query(since, tenant, bot, outcome, limit, offset)

    admin_decisions_api.set_decision_provider(provider)


def test_ndjson_keeps_details_object_from_object() -> None:
    _install_fake_store(obj_details=True)
    app = _app()
    client = TestClient(app)
    response = client.get("/admin/api/decisions/export.ndjson")
    assert response.status_code == 200
    line = response.text.strip().splitlines()[0]
    data = json.loads(line)
    assert isinstance(data["details"], dict)
    assert data["details"]["foo"] == "bar"


def test_ndjson_parses_details_string_into_object() -> None:
    _install_fake_store(obj_details=False)
    app = _app()
    client = TestClient(app)
    response = client.get("/admin/api/decisions/export.ndjson")
    assert response.status_code == 200
    line = response.text.strip().splitlines()[0]
    data = json.loads(line)
    assert isinstance(data["details"], dict)
    assert data["details"]["foo"] == "bar"


def test_csv_keeps_details_as_string() -> None:
    _install_fake_store(obj_details=True)
    app = _app()
    client = TestClient(app)
    response = client.get("/admin/api/decisions/export.csv")
    assert response.status_code == 200
    lines = response.text.strip().splitlines()
    row = lines[1]
    parsed = next(csv.reader([row]))
    assert parsed[-1] == '{"foo":"bar"}'

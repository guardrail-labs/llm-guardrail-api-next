from __future__ import annotations

import json
from typing import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.routes import admin_decisions
from app.routes.admin_ui import require_auth
from app.services import decisions_bus


@pytest.fixture(autouse=True)
def _reset_decisions_bus(tmp_path):
    old_path = getattr(decisions_bus, "_PATH")
    old_buf = getattr(decisions_bus, "_buf")
    old_max = old_buf.maxlen
    decisions_bus.configure(
        path=str(tmp_path / "decisions.jsonl"),
        max_size=1000,
        reset=True,
    )
    try:
        yield
    finally:
        decisions_bus.configure(
            path=old_path,
            max_size=old_max,
            reset=True,
        )


@pytest.fixture()
def client() -> Iterator[TestClient]:
    app = FastAPI()
    app.dependency_overrides[require_auth] = lambda: None
    app.include_router(admin_decisions.router)
    with TestClient(app) as client:
        yield client


def _publish_event(**payload):
    decisions_bus.publish(payload)


def test_request_id_filter_and_ndjson(client: TestClient) -> None:
    _publish_event(ts=10, tenant="t1", bot="b1", decision="allow", request_id="req-1")
    _publish_event(ts=20, tenant="t1", bot="b1", decision="block", request_id="req-2")
    _publish_event(ts=30, tenant="t2", bot="b2", decision="clarify", request_id="req-2")
    _publish_event(ts=40, tenant="t3", bot="b3", decision="block", request_id="req-3")

    response = client.get(
        "/admin/decisions",
        params={"request_id": "req-2", "sort": "ts_asc"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 2
    assert payload["limit"] == 50
    assert payload["offset"] == 0
    assert payload["sort"] == "ts_asc"
    items = payload["items"]
    assert [item["request_id"] for item in items] == ["req-2", "req-2"]
    assert [item["ts"] for item in items] == [20, 30]

    ndjson = client.get(
        "/admin/decisions.ndjson",
        params={"request_id": "req-2", "sort": "ts_asc"},
    )
    assert ndjson.status_code == 200
    lines = [json.loads(line) for line in ndjson.text.splitlines() if line.strip()]
    assert [entry["request_id"] for entry in lines] == ["req-2", "req-2"]
    assert [entry["ts"] for entry in lines] == [20, 30]

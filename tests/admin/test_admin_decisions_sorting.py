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


def test_sorting_uses_timestamp(client: TestClient) -> None:
    _publish_event(ts=100, request_id="r-100")
    _publish_event(ts=150, request_id="r-150")
    _publish_event(ts=50, request_id="r-050")

    asc_response = client.get(
        "/admin/decisions",
        params={"sort": "ts_asc", "limit": "10", "offset": "0"},
    )
    assert asc_response.status_code == 200
    asc_data = asc_response.json()
    assert [item["ts"] for item in asc_data["items"]] == [50, 100, 150]

    desc_response = client.get(
        "/admin/decisions",
        params={"sort": "ts_desc", "limit": "10", "offset": "0"},
    )
    assert desc_response.status_code == 200
    desc_data = desc_response.json()
    assert [item["ts"] for item in desc_data["items"]] == [150, 100, 50]


def test_pagination_after_sorting(client: TestClient) -> None:
    _publish_event(ts=100, request_id="r-100")
    _publish_event(ts=150, request_id="r-150")
    _publish_event(ts=50, request_id="r-050")

    page = client.get(
        "/admin/decisions",
        params={"sort": "ts_desc", "limit": "1", "offset": "1"},
    )
    assert page.status_code == 200
    data = page.json()
    assert data["total"] == 3
    assert [item["ts"] for item in data["items"]] == [100]


def test_ndjson_respects_timestamp_order(client: TestClient) -> None:
    _publish_event(ts=100, request_id="r-100")
    _publish_event(ts=150, request_id="r-150")
    _publish_event(ts=50, request_id="r-050")

    asc_response = client.get("/admin/decisions.ndjson", params={"sort": "ts_asc"})
    assert asc_response.status_code == 200
    asc_lines = [
        json.loads(line) for line in asc_response.text.strip().splitlines() if line.strip()
    ]
    asc_ts = [item["ts"] for item in asc_lines]
    assert asc_ts == sorted(asc_ts)

    desc_response = client.get("/admin/decisions.ndjson", params={"sort": "ts_desc"})
    assert desc_response.status_code == 200
    desc_lines = [
        json.loads(line) for line in desc_response.text.strip().splitlines() if line.strip()
    ]
    desc_ts = [item["ts"] for item in desc_lines]
    assert desc_ts == sorted(desc_ts, reverse=True)


def test_timestamp_ties_preserve_insertion_order(client: TestClient) -> None:
    _publish_event(ts=200, request_id="tie-first")
    _publish_event(ts=100, request_id="lower")
    _publish_event(ts=200, request_id="tie-second")

    asc_response = client.get(
        "/admin/decisions",
        params={"sort": "ts_asc", "limit": "10", "offset": "0"},
    )
    assert asc_response.status_code == 200
    asc_items = asc_response.json()["items"]
    assert [item["request_id"] for item in asc_items if item["ts"] == 200] == [
        "tie-first",
        "tie-second",
    ]

    desc_response = client.get(
        "/admin/decisions",
        params={"sort": "ts_desc", "limit": "10", "offset": "0"},
    )
    assert desc_response.status_code == 200
    desc_items = desc_response.json()["items"]
    assert [item["request_id"] for item in desc_items if item["ts"] == 200] == [
        "tie-first",
        "tie-second",
    ]

    desc_ndjson = client.get("/admin/decisions.ndjson", params={"sort": "ts_desc"})
    assert desc_ndjson.status_code == 200
    desc_lines = [
        json.loads(line) for line in desc_ndjson.text.strip().splitlines() if line.strip()
    ]
    assert [item["request_id"] for item in desc_lines if item["ts"] == 200] == [
        "tie-first",
        "tie-second",
    ]

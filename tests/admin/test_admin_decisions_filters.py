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


def test_basic_filters(client: TestClient) -> None:
    _publish_event(ts=100, tenant="t1", bot="b1", decision="allow")
    _publish_event(ts=110, tenant="t1", bot="b1", decision="block", rule_ids=["r-match"])
    _publish_event(ts=120, tenant="t1", bot="b2", decision="block")

    response = client.get(
        "/admin/decisions",
        params={"tenant": "t1", "bot": "b1", "decision": "block"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["limit"] == 50
    assert data["offset"] == 0
    assert data["sort"] == "ts_desc"
    assert len(data["items"]) == 1
    item = data["items"][0]
    assert item["tenant"] == "t1"
    assert item["bot"] == "b1"
    assert item["decision"] == "block"


def test_rule_id_filter_matches_lists_and_single_values(client: TestClient) -> None:
    _publish_event(ts=200, tenant="t1", bot="b1", decision="allow", rule_ids=["r-a", "r-b"])
    _publish_event(ts=210, tenant="t1", bot="b1", decision="allow", rule_id="r-c")
    _publish_event(ts=220, tenant="t1", bot="b1", decision="allow")

    response = client.get("/admin/decisions", params={"rule_id": "r-b", "sort": "ts_asc"})
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["rule_ids"] == ["r-a", "r-b"]

    response_single = client.get("/admin/decisions", params={"rule_id": "r-c"})
    assert response_single.status_code == 200
    data_single = response_single.json()
    assert data_single["total"] == 1
    assert data_single["items"][0]["rule_id"] == "r-c"


def test_time_window_and_sorting(client: TestClient) -> None:
    _publish_event(ts=300, tenant="t1", bot="b1", decision="allow")
    _publish_event(ts=310, tenant="t1", bot="b1", decision="block")
    _publish_event(ts=320, tenant="t1", bot="b1", decision="clarify")

    response = client.get(
        "/admin/decisions",
        params={"from_ts": "305", "to_ts": "321", "sort": "ts_asc"},
    )
    assert response.status_code == 200
    data = response.json()
    ts_values = [item["ts"] for item in data["items"]]
    assert ts_values == [310, 320]


def test_pagination_uses_limit_and_offset(client: TestClient) -> None:
    for idx in range(5):
        _publish_event(ts=400 + idx, tenant="t1", bot="b1", decision="redact")

    first_page = client.get(
        "/admin/decisions",
        params={"tenant": "t1", "limit": "2", "offset": "0", "sort": "ts_asc"},
    )
    assert first_page.status_code == 200
    data_first = first_page.json()
    assert data_first["total"] == 5
    assert [item["ts"] for item in data_first["items"]] == [400, 401]

    second_page = client.get(
        "/admin/decisions",
        params={"tenant": "t1", "limit": "2", "offset": "2", "sort": "ts_asc"},
    )
    assert second_page.status_code == 200
    data_second = second_page.json()
    assert data_second["total"] == 5
    assert [item["ts"] for item in data_second["items"]] == [402, 403]


def test_ndjson_export_matches_filtered_items(client: TestClient) -> None:
    for idx in range(3):
        _publish_event(
            ts=500 + idx,
            tenant="t1",
            bot="b1",
            decision="allow",
            request_id=f"req-{idx}",
        )

    json_response = client.get(
        "/admin/decisions",
        params={"tenant": "t1", "sort": "ts_desc"},
    )
    assert json_response.status_code == 200
    items = json_response.json()["items"]

    ndjson_response = client.get(
        "/admin/decisions.ndjson",
        params={"tenant": "t1", "sort": "ts_desc"},
    )
    assert ndjson_response.status_code == 200
    lines = [json.loads(line) for line in ndjson_response.text.strip().splitlines() if line]
    assert [item["request_id"] for item in lines] == [item["request_id"] for item in items]


def test_validation_errors_return_standard_payload(client: TestClient) -> None:
    bad_decision = client.get("/admin/decisions", params={"decision": "nope"})
    assert bad_decision.status_code == 400
    assert bad_decision.json() == {"error": "invalid decision"}

    bad_limit = client.get("/admin/decisions", params={"limit": "0"})
    assert bad_limit.status_code == 400
    assert bad_limit.json() == {"error": "limit must be >= 1"}

    bad_offset = client.get("/admin/decisions", params={"offset": "-1"})
    assert bad_offset.status_code == 400
    assert bad_offset.json() == {"error": "offset must be >= 0"}

    bad_range = client.get(
        "/admin/decisions",
        params={"from_ts": "200", "to_ts": "100"},
    )
    assert bad_range.status_code == 400
    assert bad_range.json() == {"error": "to_ts must be greater than from_ts"}

    bad_sort = client.get("/admin/decisions.ndjson", params={"sort": "oops"})
    assert bad_sort.status_code == 400
    assert bad_sort.json() == {"error": "sort must be one of ts_desc or ts_asc"}

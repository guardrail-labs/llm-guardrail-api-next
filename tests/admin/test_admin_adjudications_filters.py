from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Iterator, Optional

import pytest
from fastapi.testclient import TestClient

import app.observability.adjudication_log as adjudication_log


def _admin_headers(key: str = "secret") -> dict[str, str]:
    return {"X-Admin-Key": key}


def _ts(dt: datetime) -> str:
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _append_record(
    *,
    dt: datetime,
    request_id: str,
    tenant: str,
    bot: str,
    provider: str,
    decision: str,
    mitigation_forced: Optional[str] = None,
) -> None:
    record = adjudication_log.AdjudicationRecord(
        ts=_ts(dt),
        request_id=request_id,
        tenant=tenant,
        bot=bot,
        provider=provider,
        decision=decision,
        rule_hits=["rule:test"],
        score=None,
        latency_ms=25,
        policy_version="v1",
        rules_path="/rules/path",
        sampled=False,
        prompt_sha256=None,
    )
    if mitigation_forced is not None:
        setattr(record, "mitigation_forced", mitigation_forced)
    adjudication_log.append(record)


@pytest.fixture
def admin_client(client: TestClient) -> Iterator[TestClient]:
    adjudication_log.clear()
    try:
        yield client
    finally:
        adjudication_log.clear()


def test_basic_filters(admin_client: TestClient) -> None:
    now = datetime.now(timezone.utc)
    _append_record(
        dt=now,
        request_id="r1",
        tenant="t1",
        bot="b1",
        provider="core",
        decision="block",
        mitigation_forced="clarify",
    )
    _append_record(
        dt=now - timedelta(seconds=5),
        request_id="r2",
        tenant="t1",
        bot="b1",
        provider="core",
        decision="block",
    )
    _append_record(
        dt=now - timedelta(seconds=10),
        request_id="r3",
        tenant="t2",
        bot="b2",
        provider="verifier",
        decision="allow",
    )

    response = admin_client.get(
        "/admin/adjudications",
        params={"tenant": "t1", "bot": "b1", "decision": "block"},
        headers=_admin_headers(),
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 2
    assert payload["limit"] == 50
    assert payload["offset"] == 0
    assert payload["sort"] == "ts_desc"
    ids = [item["request_id"] for item in payload["items"]]
    assert ids == ["r1", "r2"]

    clarify_only = admin_client.get(
        "/admin/adjudications",
        params={
            "tenant": "t1",
            "decision": "block",
            "mitigation_forced": "clarify",
        },
        headers=_admin_headers(),
    ).json()
    assert clarify_only["total"] == 1
    assert [item["request_id"] for item in clarify_only["items"]] == ["r1"]

    none_forced = admin_client.get(
        "/admin/adjudications",
        params={"tenant": "t1", "mitigation_forced": ""},
        headers=_admin_headers(),
    ).json()
    none_ids = [item["request_id"] for item in none_forced["items"]]
    assert none_ids == ["r2"]
    assert all(item.get("mitigation_forced") in (None, "") for item in none_forced["items"])


def test_time_filters_and_sort(admin_client: TestClient) -> None:
    base = datetime.now(timezone.utc) - timedelta(minutes=5)
    for idx in range(4):
        _append_record(
            dt=base + timedelta(minutes=idx),
            request_id=f"time-{idx}",
            tenant="time-tenant",
            bot="time-bot",
            provider="core",
            decision="allow" if idx % 2 == 0 else "block",
        )

    start = int((base + timedelta(minutes=1)).timestamp())
    end = int((base + timedelta(minutes=3)).timestamp())

    response = admin_client.get(
        "/admin/adjudications",
        params={
            "tenant": "time-tenant",
            "from_ts": str(start),
            "to_ts": str(end),
            "sort": "ts_asc",
        },
        headers=_admin_headers(),
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 2
    ids = [item["request_id"] for item in payload["items"]]
    assert ids == ["time-1", "time-2"]


def test_pagination_returns_total(admin_client: TestClient) -> None:
    base = datetime.now(timezone.utc)
    inserted = []
    for idx in range(5):
        request_id = f"page-{idx}"
        inserted.append(request_id)
        _append_record(
            dt=base + timedelta(seconds=idx),
            request_id=request_id,
            tenant="page-tenant",
            bot="page-bot",
            provider="core",
            decision="allow",
        )

    response = admin_client.get(
        "/admin/adjudications",
        params={
            "tenant": "page-tenant",
            "bot": "page-bot",
            "limit": "2",
            "offset": "1",
            "sort": "ts_desc",
        },
        headers=_admin_headers(),
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 5
    assert payload["limit"] == 2
    assert payload["offset"] == 1
    expected_order = list(reversed(inserted))
    assert [item["request_id"] for item in payload["items"]] == expected_order[1:3]


def test_ndjson_mirrors_filters(admin_client: TestClient) -> None:
    base = datetime.now(timezone.utc)
    for idx in range(3):
        _append_record(
            dt=base + timedelta(seconds=idx),
            request_id=f"ndjson-{idx}",
            tenant="ndjson-tenant",
            bot="ndjson-bot",
            provider="core",
            decision="clarify",
            mitigation_forced="redact" if idx == 1 else None,
        )

    params = {
        "tenant": "ndjson-tenant",
        "bot": "ndjson-bot",
        "decision": "clarify",
        "sort": "ts_desc",
    }
    json_listing = admin_client.get(
        "/admin/adjudications",
        params=params,
        headers=_admin_headers(),
    ).json()["items"]

    ndjson_response = admin_client.get(
        "/admin/adjudications.ndjson",
        params=params,
        headers=_admin_headers(),
    )
    assert ndjson_response.status_code == 200
    lines = [line for line in ndjson_response.text.splitlines() if line.strip()]
    parsed = [json.loads(line) for line in lines]
    parsed_ids = [entry["request_id"] for entry in parsed]
    json_ids = [item["request_id"] for item in json_listing]
    assert parsed_ids == json_ids


def test_validation_errors(admin_client: TestClient) -> None:
    bad_decision = admin_client.get(
        "/admin/adjudications",
        params={"decision": "maybe"},
        headers=_admin_headers(),
    )
    assert bad_decision.status_code == 400
    assert bad_decision.json()["error"] == "invalid decision"

    negative_limit = admin_client.get(
        "/admin/adjudications",
        params={"limit": "-5"},
        headers=_admin_headers(),
    )
    assert negative_limit.status_code == 400
    assert negative_limit.json()["error"] == "limit must be >= 1"

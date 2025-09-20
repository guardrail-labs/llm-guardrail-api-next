from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Iterator

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
    adjudication_log.append(record)


@pytest.fixture
def admin_client(client: TestClient) -> Iterator[TestClient]:
    adjudication_log.clear()
    try:
        yield client
    finally:
        adjudication_log.clear()


def test_request_id_filter_and_ndjson(admin_client: TestClient) -> None:
    base = datetime.now(timezone.utc)
    _append_record(
        dt=base - timedelta(seconds=2),
        request_id="req-1",
        tenant="tenant-1",
        bot="bot-1",
        provider="core",
        decision="allow",
    )
    _append_record(
        dt=base - timedelta(seconds=1),
        request_id="req-2",
        tenant="tenant-2",
        bot="bot-2",
        provider="core",
        decision="block",
    )
    _append_record(
        dt=base,
        request_id="req-2",
        tenant="tenant-3",
        bot="bot-3",
        provider="core",
        decision="clarify",
    )
    _append_record(
        dt=base + timedelta(seconds=1),
        request_id="req-3",
        tenant="tenant-4",
        bot="bot-4",
        provider="core",
        decision="allow",
    )

    response = admin_client.get(
        "/admin/adjudications",
        params={"request_id": "req-2", "sort": "ts_asc"},
        headers=_admin_headers(),
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 2
    assert payload["limit"] == 50
    assert payload["offset"] == 0
    assert payload["sort"] == "ts_asc"
    items = payload["items"]
    assert [item["request_id"] for item in items] == ["req-2", "req-2"]
    assert [item["ts"] for item in items] == sorted([item["ts"] for item in items])

    ndjson = admin_client.get(
        "/admin/adjudications.ndjson",
        params={"request_id": "req-2", "sort": "ts_asc"},
        headers=_admin_headers(),
    )
    assert ndjson.status_code == 200
    lines = [json.loads(line) for line in ndjson.text.splitlines() if line.strip()]
    assert [entry["request_id"] for entry in lines] == ["req-2", "req-2"]
    assert [entry["ts"] for entry in lines] == [item["ts"] for item in items]

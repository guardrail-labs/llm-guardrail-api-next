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
    rule_id: str | None,
) -> None:
    record = adjudication_log.AdjudicationRecord(
        ts=_ts(dt),
        request_id=request_id,
        tenant="tenant-1",
        bot="bot-1",
        provider="core",
        decision="block",
        rule_hits=["rule:test"],
        score=None,
        latency_ms=15,
        policy_version="v1",
        rules_path="/rules/path",
        sampled=False,
        prompt_sha256=None,
    )
    if rule_id is not None:
        setattr(record, "rule_id", rule_id)
    adjudication_log.append(record)


@pytest.fixture
def admin_client(client: TestClient) -> Iterator[TestClient]:
    adjudication_log.clear()
    try:
        yield client
    finally:
        adjudication_log.clear()


def test_rule_id_filter_matches_only_requested(admin_client: TestClient) -> None:
    now = datetime.now(timezone.utc)
    _append_record(dt=now, request_id="match-1", rule_id="r-42")
    _append_record(dt=now - timedelta(seconds=5), request_id="skip-1", rule_id="r-99")
    _append_record(dt=now - timedelta(seconds=10), request_id="skip-2", rule_id=None)

    response = admin_client.get(
        "/admin/adjudications",
        params={"rule_id": "r-42"},
        headers=_admin_headers(),
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert [item.get("request_id") for item in payload["items"]] == ["match-1"]
    assert [item.get("rule_id") for item in payload["items"]] == ["r-42"]


def test_rule_id_filter_applies_to_ndjson(admin_client: TestClient) -> None:
    base = datetime.now(timezone.utc)
    _append_record(dt=base - timedelta(seconds=1), request_id="match-old", rule_id="r-7")
    _append_record(dt=base, request_id="match-new", rule_id="r-7")
    _append_record(dt=base + timedelta(seconds=1), request_id="skip", rule_id="r-other")

    response = admin_client.get(
        "/admin/adjudications.ndjson",
        params={"rule_id": "r-7"},
        headers=_admin_headers(),
    )
    assert response.status_code == 200
    lines = [line for line in response.text.splitlines() if line.strip()]
    assert lines, "expected ndjson output"
    parsed = [json.loads(line) for line in lines]
    assert [entry["rule_id"] for entry in parsed] == ["r-7", "r-7"]
    assert [entry["request_id"] for entry in parsed] == ["match-new", "match-old"]

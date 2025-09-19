import hashlib
import importlib
import json
from datetime import datetime, timedelta, timezone
from typing import Iterator, List, TypedDict

import pytest
from fastapi.testclient import TestClient

import app.observability.adjudication_log as adjudication_log


class _Entry(TypedDict):
    tenant: str
    bot: str
    request_id: str
    provider: str
    prompt: str
    decision: str
    ts: datetime


def _admin_headers(key: str = "secret") -> dict[str, str]:
    return {"X-Admin-Key": key}


def _ts(dt: datetime) -> str:
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


@pytest.fixture
def admin_client(client: TestClient) -> Iterator[TestClient]:
    adjudication_log.clear()
    try:
        yield client
    finally:
        adjudication_log.clear()


def _append_record(
    *,
    ts: datetime,
    request_id: str,
    tenant: str,
    bot: str,
    provider: str,
    decision: str,
    rule_hits: List[str],
    score: float | None,
    latency_ms: int,
    policy_version: str | None,
    rules_path: str | None,
    sampled: bool,
    prompt: str | None,
) -> None:
    prompt_sha = hashlib.sha256(prompt.encode("utf-8")).hexdigest() if prompt else None
    adjudication_log.append(
        adjudication_log.AdjudicationRecord(
            ts=_ts(ts),
            request_id=request_id,
            tenant=tenant,
            bot=bot,
            provider=provider,
            decision=decision,
            rule_hits=rule_hits,
            score=score,
            latency_ms=latency_ms,
            policy_version=policy_version,
            rules_path=rules_path,
            sampled=sampled,
            prompt_sha256=prompt_sha,
        )
    )


def test_adjudication_logs_list_contains_records(admin_client: TestClient) -> None:
    now = datetime.now(timezone.utc)
    _append_record(
        ts=now,
        request_id="req-allow",
        tenant="tenant-a",
        bot="bot-1",
        provider="core",
        decision="allow",
        rule_hits=["rule:allow"],
        score=None,
        latency_ms=42,
        policy_version="v1",
        rules_path="/path/to/policy",
        sampled=False,
        prompt="hello world",
    )

    response = admin_client.get("/admin/adjudications", headers=_admin_headers())
    assert response.status_code == 200
    body = response.json()
    assert "items" in body
    items: List[dict] = body["items"]
    assert items, "expected adjudication records"
    first = items[0]
    assert first["request_id"] == "req-allow"
    assert first["tenant"] == "tenant-a"
    assert first["bot"] == "bot-1"
    assert first["decision"] == "allow"
    assert isinstance(first["latency_ms"], int)
    assert first["latency_ms"] == 42
    assert first["provider"] == "core"
    assert first["prompt_sha256"] == hashlib.sha256(b"hello world").hexdigest()
    assert "prompt" not in first
    assert "text" not in first


def test_adjudication_filters_and_limits(admin_client: TestClient) -> None:
    now = datetime.now(timezone.utc) - timedelta(minutes=5)
    entries: list[_Entry] = [
        {
            "tenant": "tenant-a",
            "bot": "bot-1",
            "request_id": "req-a",
            "provider": "core",
            "prompt": "alpha",
            "decision": "allow",
            "ts": now,
        },
        {
            "tenant": "tenant-b",
            "bot": "bot-2",
            "request_id": "req-b",
            "provider": "verifier-x",
            "prompt": "bravo",
            "decision": "block",
            "ts": now + timedelta(minutes=1),
        },
        {
            "tenant": "tenant-a",
            "bot": "bot-3",
            "request_id": "req-c",
            "provider": "core",
            "prompt": "charlie",
            "decision": "clarify",
            "ts": now + timedelta(minutes=2),
        },
    ]
    for entry in entries:
        _append_record(
            ts=entry["ts"],
            request_id=entry["request_id"],
            tenant=entry["tenant"],
            bot=entry["bot"],
            provider=entry["provider"],
            decision=entry["decision"],
            rule_hits=["rule:test"],
            score=None,
            latency_ms=30,
            policy_version="v1",
            rules_path="/rules",
            sampled=False,
            prompt=entry["prompt"],
        )

    base = admin_client.get("/admin/adjudications", headers=_admin_headers())
    assert base.status_code == 200
    all_items = base.json()["items"]
    assert len(all_items) == len(entries)

    tenant_only = admin_client.get(
        "/admin/adjudications",
        params={"tenant": "tenant-b"},
        headers=_admin_headers(),
    ).json()["items"]
    assert [r["request_id"] for r in tenant_only] == ["req-b"]

    bot_only = admin_client.get(
        "/admin/adjudications",
        params={"bot": "bot-3"},
        headers=_admin_headers(),
    ).json()["items"]
    assert [r["request_id"] for r in bot_only] == ["req-c"]

    provider_matches = admin_client.get(
        "/admin/adjudications",
        params={"provider": "verifier-x"},
        headers=_admin_headers(),
    ).json()["items"]
    assert [r["request_id"] for r in provider_matches] == ["req-b"]

    none_provider = admin_client.get(
        "/admin/adjudications",
        params={"provider": "no-such-provider"},
        headers=_admin_headers(),
    ).json()["items"]
    assert none_provider == []

    single = admin_client.get(
        "/admin/adjudications",
        params={"request_id": "req-b"},
        headers=_admin_headers(),
    ).json()["items"]
    assert [r["request_id"] for r in single] == ["req-b"]

    newest_ts = entries[-1]["ts"] + timedelta(seconds=1)
    start_filtered = admin_client.get(
        "/admin/adjudications",
        params={"start": _ts(newest_ts)},
        headers=_admin_headers(),
    ).json()["items"]
    assert start_filtered == []

    oldest_ts = entries[0]["ts"]
    end_filtered = admin_client.get(
        "/admin/adjudications",
        params={"end": _ts(oldest_ts)},
        headers=_admin_headers(),
    ).json()["items"]
    assert [r["request_id"] for r in end_filtered] == ["req-a"]

    limit_one = admin_client.get(
        "/admin/adjudications",
        params={"limit": 1},
        headers=_admin_headers(),
    ).json()["items"]
    assert len(limit_one) == 1

    capped = admin_client.get(
        "/admin/adjudications",
        params={"limit": 5000},
        headers=_admin_headers(),
    ).json()["items"]
    assert len(capped) == len(all_items)


def test_adjudication_ndjson_export(admin_client: TestClient) -> None:
    now = datetime.now(timezone.utc)
    for idx in range(3):
        _append_record(
            ts=now + timedelta(seconds=idx),
            request_id=f"req-export-{idx}",
            tenant="tenant-z",
            bot="bot-z",
            provider="core",
            decision="allow",
            rule_hits=["rule:ndjson"],
            score=None,
            latency_ms=25,
            policy_version=None,
            rules_path=None,
            sampled=False,
            prompt=f"export-{idx}",
        )

    json_list = admin_client.get(
        "/admin/adjudications",
        params={"tenant": "tenant-z"},
        headers=_admin_headers(),
    ).json()["items"]

    response = admin_client.get(
        "/admin/adjudications.ndjson",
        params={"tenant": "tenant-z"},
        headers=_admin_headers(),
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-ndjson")
    lines = [ln for ln in response.text.splitlines() if ln.strip()]
    parsed = [json.loads(line) for line in lines]
    assert len(parsed) == len(json_list)
    for entry in parsed:
        assert entry["prompt_sha256"]
        assert "prompt" not in entry


def test_adjudication_ring_buffer_cap(monkeypatch) -> None:
    import app.observability.adjudication_log as adj

    monkeypatch.setenv("ADJUDICATION_LOG_CAP", "3")
    importlib.reload(adj)

    for idx in range(5):
        record = adj.AdjudicationRecord(
            ts=adj._now_ts(),
            request_id=f"req-{idx}",
            tenant="tenant",
            bot="bot",
            provider="core",
            decision="allow",
            rule_hits=[],
            score=None,
            latency_ms=5,
            policy_version=None,
            rules_path=None,
            sampled=False,
            prompt_sha256=None,
        )
        adj.append(record)

    items = adj.query(limit=10)
    assert len(items) == 3
    assert [rec.request_id for rec in items] == ["req-4", "req-3", "req-2"]

    monkeypatch.setenv("ADJUDICATION_LOG_CAP", "10000")
    importlib.reload(adj)

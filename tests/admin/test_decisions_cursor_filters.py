from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi.testclient import TestClient

from app.services import decisions_store


def _mk_record(
    ts_ms: int,
    request_id: str,
    *,
    outcome: str = "allow",
    tenant: str = "t",
    bot: str = "b",
) -> Dict[str, Any]:
    ts = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
    return {
        "id": f"{request_id}-id",
        "ts": ts,
        "ts_ms": ts_ms,
        "tenant": tenant,
        "bot": bot,
        "outcome": outcome,
        "request_id": request_id,
    }


def test_filters_applied_before_cursor(monkeypatch) -> None:
    base = 1_700_000_000_000
    records: List[Dict[str, Any]] = [
        _mk_record(base + 10, "A", outcome="block"),
        _mk_record(base + 10, "B", outcome="allow"),
        _mk_record(base + 5, "C", outcome="block"),
        _mk_record(base + 0, "D", outcome="clarify"),
    ]

    def fake_fetch(**_: Any) -> List[Dict[str, Any]]:
        return sorted(records, key=lambda r: (r["ts_ms"], r["id"]), reverse=True)

    monkeypatch.setattr(decisions_store, "_fetch_decisions_sorted_desc", fake_fetch)

    page1, next_cursor, prev_cursor = decisions_store.list_with_cursor(limit=1, outcome="block")
    assert [item["request_id"] for item in page1] == ["A"]
    assert next_cursor is not None
    assert prev_cursor is None

    page2, next_cursor2, prev_cursor2 = decisions_store.list_with_cursor(
        limit=5,
        cursor=next_cursor,
        dir="next",
        outcome="block",
    )
    assert [item["request_id"] for item in page2] == ["C"]
    assert next_cursor2 is None
    assert prev_cursor2 is not None


def test_route_respects_filters_and_invalid_cursor(
    client: TestClient, monkeypatch
) -> None:
    base = 1_700_000_000_000
    records = [
        _mk_record(base + 1, "RID-X", outcome="allow"),
        _mk_record(base + 2, "RID-Y", outcome="block"),
    ]

    def fake_fetch(
        *,
        tenant: str | None,
        bot: str | None,
        limit: int,
        cursor: tuple[int, str] | None,
        dir: str,
        since_ts_ms: int | None = None,
        outcome: str | None = None,
        request_id: str | None = None,
    ) -> List[Dict[str, Any]]:
        _ = (cursor, dir)
        filtered = sorted(records, key=lambda r: (r["ts_ms"], r["id"]), reverse=True)
        if tenant:
            filtered = [rec for rec in filtered if rec["tenant"] == tenant]
        if bot:
            filtered = [rec for rec in filtered if rec["bot"] == bot]
        if since_ts_ms is not None:
            filtered = [rec for rec in filtered if rec["ts_ms"] >= since_ts_ms]
        if outcome:
            filtered = [rec for rec in filtered if rec["outcome"] == outcome]
        if request_id:
            filtered = [rec for rec in filtered if rec["request_id"] == request_id]
        return filtered[:limit]

    monkeypatch.setattr(decisions_store, "_fetch_decisions_sorted_desc", fake_fetch)

    since_iso = datetime.fromtimestamp((base + 2) / 1000, tz=timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    response = client.get(
        "/admin/api/decisions",
        params={"since": since_iso, "request_id": "RID-Y", "limit": 10},
    )
    assert response.status_code == 200
    payload = response.json()
    assert [item["id"] for item in payload["items"]] == ["RID-Y-id"]

    bad_cursor = client.get("/admin/api/decisions", params={"cursor": "==broken=="})
    assert bad_cursor.status_code == 400

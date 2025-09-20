from datetime import datetime, timezone


def test_cursor_respects_since_and_outcome(monkeypatch, client):
    from app.services import decisions_store as store

    base = 1_700_000_000_000
    items = [
        {"id": "a", "ts_ms": base + 3, "outcome": "block"},
        {"id": "b", "ts_ms": base + 2, "outcome": "allow"},
        {"id": "c", "ts_ms": base + 1, "outcome": "block"},
        {"id": "d", "ts_ms": base + 0, "outcome": "clarify"},
    ]

    captured_kwargs = {}

    def fetch(**kwargs):
        captured_kwargs.update(kwargs)
        records = list(items)
        since_ts = kwargs.get("since_ts_ms")
        outcome = kwargs.get("outcome")
        if since_ts is not None:
            records = [x for x in records if x["ts_ms"] >= since_ts]
        if outcome is not None:
            records = [x for x in records if x.get("outcome") == outcome]
        return sorted(records, key=lambda x: (x["ts_ms"], x["id"]), reverse=True)

    monkeypatch.setattr(store, "_fetch_decisions_sorted_desc", fetch)

    since_iso = datetime.fromtimestamp((base + 1) / 1000, tz=timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    response = client.get(
        "/admin/api/decisions",
        params={"limit": 2, "since": since_iso, "outcome": "block"},
    )
    assert response.status_code == 200
    payload = response.json()

    assert captured_kwargs.get("since_ts_ms") == base + 1
    assert captured_kwargs.get("outcome") == "block"

    ids = [item["id"] for item in payload["items"]]
    assert ids == ["a", "c"]
    assert all(item["outcome"].lower() == "block" for item in payload["items"])

from __future__ import annotations

from app.utils.cursor import encode_cursor


def _mk(id_i: int, ts_ms: int):
    return {"id": f"{id_i:032x}", "ts_ms": ts_ms, "payload": id_i}


def test_forward_paging_basic(monkeypatch):
    base = 1_700_000_000_000
    items = [_mk(i, base + (100 - i)) for i in range(100)]

    from app.services import decisions_store as store

    monkeypatch.setattr(
        store,
        "_fetch_decisions_sorted_desc",
        lambda **_: sorted(items, key=lambda x: (x["ts_ms"], x["id"]), reverse=True),
    )

    page, next_cursor, prev_cursor = store.list_with_cursor(limit=25)
    assert len(page) == 25
    assert next_cursor and prev_cursor is None

    total = len(page)
    cursor = next_cursor
    while cursor:
        page, cursor, prev_cursor = store.list_with_cursor(limit=25, cursor=cursor, dir="next")
        total += len(page)
    assert total == len(items)


def test_interleaved_inserts_no_gaps_or_dupes(monkeypatch):
    base = 1_700_000_000_000
    items = [_mk(i, base + (100 - i)) for i in range(100)]

    from app.services import decisions_store as store

    def fetch(**_):
        return sorted(items, key=lambda x: (x["ts_ms"], x["id"]), reverse=True)

    monkeypatch.setattr(store, "_fetch_decisions_sorted_desc", lambda **_: fetch())

    page1, next_cursor, prev_cursor = store.list_with_cursor(limit=20)
    boundary = page1[-1]
    items.extend([_mk(1000, base + 1000), _mk(1001, base + 1001)])

    page2, next_cursor2, prev_cursor2 = store.list_with_cursor(
        limit=20,
        cursor=encode_cursor(boundary["ts_ms"], boundary["id"]),
        dir="next",
    )

    ids_seen = {x["id"] for x in page1}
    assert not any(x["id"] in ids_seen for x in page2)


def test_prev_paging_roundtrip(monkeypatch):
    base = 1_700_000_000_000
    items = [_mk(i, base + (50 - i)) for i in range(50)]

    from app.services import decisions_store as store

    monkeypatch.setattr(
        store,
        "_fetch_decisions_sorted_desc",
        lambda **_: sorted(items, key=lambda x: (x["ts_ms"], x["id"]), reverse=True),
    )

    page1, next_cursor, prev_cursor = store.list_with_cursor(limit=10)
    assert len(page1) == 10 and next_cursor and prev_cursor is None

    page2, next_cursor2, prev_cursor2 = store.list_with_cursor(
        limit=10,
        cursor=next_cursor,
        dir="next",
    )
    page1_back, next_cursor_back, prev_cursor_back = store.list_with_cursor(
        limit=10,
        cursor=prev_cursor2,
        dir="prev",
    )
    assert [x["id"] for x in page1] == [x["id"] for x in page1_back]


def test_invalid_cursor_raises_400(client):
    response = client.get("/admin/api/decisions", params={"cursor": "==broken=="})
    assert response.status_code == 400


def test_offset_back_compat_warns(caplog, client):
    caplog.set_level("WARNING")
    response = client.get("/admin/api/decisions", params={"limit": 5, "offset": 0})
    assert response.status_code == 200
    assert any("deprecated" in record.message.lower() for record in caplog.records)

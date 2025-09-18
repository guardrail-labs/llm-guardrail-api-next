from datetime import datetime, timedelta, timezone

from app.services import decisions as store


def test_insert_and_query_sqlite(tmp_path, monkeypatch):
    dsn = f"sqlite:///{tmp_path}/decisions.db"
    monkeypatch.setenv("DECISIONS_DSN", dsn)
    import importlib

    importlib.reload(store)

    now = datetime.now(timezone.utc)
    store.record(
        id="a1",
        ts=now - timedelta(minutes=2),
        tenant="t1",
        bot="b1",
        outcome="allow",
        policy_version="v1",
    )
    store.record(
        id="a2",
        ts=now - timedelta(minutes=1),
        tenant="t1",
        bot="b2",
        outcome="block_input_only",
        rule_id="r1",
    )
    store.record(id="a3", ts=now, tenant="t2", bot="b1", outcome="allow")

    items, total = store.query(None, None, None, None, limit=10, offset=0)
    assert total == 3
    assert items[0]["id"] == "a3"

    items_t1, total_t1 = store.query(None, "t1", None, None, 10, 0)
    assert total_t1 == 2

    items_since, total_since = store.query(
        now - timedelta(minutes=1, seconds=30),
        None,
        None,
        None,
        10,
        0,
    )
    assert total_since == 2


def test_prune(tmp_path, monkeypatch):
    dsn = f"sqlite:///{tmp_path}/decisions.db"
    monkeypatch.setenv("DECISIONS_DSN", dsn)
    monkeypatch.setenv("DECISIONS_PRUNE_DAYS", "1")
    import importlib

    importlib.reload(store)

    old = datetime.now(timezone.utc) - timedelta(days=2)
    store.record(id="old", ts=old, tenant="t", bot="b", outcome="allow")
    store.record(id="new", ts=datetime.now(timezone.utc), tenant="t", bot="b", outcome="allow")
    deleted = store.prune(older_than_days=1)
    items, total = store.query(None, None, None, None, 100, 0)
    assert deleted >= 1
    assert any(x["id"] == "new" for x in items)

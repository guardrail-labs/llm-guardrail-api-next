from datetime import datetime, timezone

from app.observability import adjudication_log as log


def _record(ts: str, request_id: str) -> log.AdjudicationRecord:
    return log.AdjudicationRecord(
        ts=ts,
        request_id=request_id,
        tenant="tenant",
        bot="bot",
        provider="provider",
        decision="allow",
        rule_hits=[],
        score=None,
        latency_ms=0,
        policy_version=None,
        rules_path=None,
        sampled=False,
        prompt_sha256=None,
    )


def test_equal_timestamp_cursor_uses_index_tiebreak():
    log.clear()

    ts_shared = (
        datetime(2024, 1, 1, 0, 0, tzinfo=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )
    ts_older = (
        datetime(2023, 12, 31, 23, 59, tzinfo=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )

    first = _record(ts_shared, "req-1")
    second = _record(ts_shared, "req-2")
    third = _record(ts_older, "req-3")

    log.append(first)
    log.append(second)
    log.append(third)

    page1, next_cursor, prev_cursor = log.list_with_cursor(limit=1)
    assert [rec.request_id for rec in page1] == ["req-2"]
    assert next_cursor is not None and prev_cursor is None

    page2, next_cursor2, prev_cursor2 = log.list_with_cursor(
        limit=1,
        cursor=next_cursor,
        dir="next",
    )
    assert [rec.request_id for rec in page2] == ["req-1"]
    assert next_cursor2 is not None
    assert prev_cursor2 is not None

    page3, _, _ = log.list_with_cursor(limit=1, cursor=next_cursor2, dir="next")
    assert [rec.request_id for rec in page3] == ["req-3"]

    log.clear()

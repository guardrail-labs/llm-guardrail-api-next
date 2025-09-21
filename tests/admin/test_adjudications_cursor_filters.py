from __future__ import annotations

from datetime import datetime, timezone

from app.observability import adjudication_log as log


def _rec(
    ts_ms: int,
    request_id: str,
    decision: str = "allow",
    rule_hits: list[dict[str, str]] | None = None,
    tenant: str = "t",
    bot: str = "b",
):
    return log.AdjudicationRecord(
        ts=datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
        request_id=request_id,
        tenant=tenant,
        bot=bot,
        provider="p",
        decision=decision,
        rule_hits=rule_hits or [],
        score=None,
        latency_ms=0,
        policy_version=None,
        rules_path=None,
        sampled=False,
        prompt_sha256=None,
    )


def teardown_function(_f=None):
    log.clear()


def test_filters_before_cursor():
    log.clear()
    base = 1_700_000_000_000
    a = _rec(base + 10, "A", decision="block", rule_hits=[{"rule_id": "R1"}])
    b = _rec(base + 10, "B", decision="allow", rule_hits=[{"rule_id": "R2"}])
    c = _rec(base + 5, "C", decision="block", rule_hits=[{"rule_id": "R1"}])
    d = _rec(base + 0, "D", decision="clarify", rule_hits=[])
    for rec in (a, b, c, d):
        log.append(rec)

    page1, nxt, prv = log.list_with_cursor(limit=1, outcome="block", rule_id="R1")
    assert [r.request_id for r in page1] == ["A"]
    assert nxt is not None and prv is None

    page2, nxt2, prv2 = log.list_with_cursor(
        limit=5,
        cursor=nxt,
        dir="next",
        outcome="block",
        rule_id="R1",
    )
    assert [r.request_id for r in page2] == ["C"]
    assert nxt2 is None
    assert prv2 is not None


def test_request_id_and_since_route(client):
    log.clear()
    base = 1_700_000_000_000
    x = _rec(base + 1, "RID-X")
    y = _rec(base + 2, "RID-Y")
    log.append(x)
    log.append(y)

    response = client.get(
        "/admin/api/adjudications",
        params={"since": base + 2, "request_id": "RID-Y", "limit": 10},
    )
    assert response.status_code == 200
    ids = [item["request_id"] for item in response.json()["items"]]
    assert ids == ["RID-Y"]

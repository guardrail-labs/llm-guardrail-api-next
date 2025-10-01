from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple, cast

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.routes import admin_decisions_api as dec


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(dec.router)
    return app


def _sample_items(now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """Return sample decisions anchored to the provided time."""

    if now is None:
        now = datetime.now(timezone.utc)

    return [
        {
            "id": "a1",
            "ts": now - timedelta(minutes=5),
            "tenant": "t1",
            "bot": "b1",
            "outcome": "allow",
            "policy_version": "v1",
        },
        {
            "id": "a2",
            "ts": now - timedelta(minutes=3),
            "tenant": "t1",
            "bot": "b2",
            "outcome": "block_input_only",
            "policy_version": "v1",
            "rule_id": "r-secret",
        },
        {
            "id": "a3",
            "ts": now - timedelta(minutes=1),
            "tenant": "t2",
            "bot": "b1",
            "outcome": "allow",
            "policy_version": "v2",
        },
    ]


def _provider(
    since, tenant, bot, outcome, limit, offset
) -> Tuple[List[Dict[str, Any]], Optional[int]]:
    rows = _sample_items()
    if since:
        rows = [x for x in rows if x["ts"] >= since]
    if tenant:
        rows = [x for x in rows if x.get("tenant") == tenant]
    if bot:
        rows = [x for x in rows if x.get("bot") == bot]
    if outcome:
        rows = [x for x in rows if x.get("outcome") == outcome]
    rows_sorted = sorted(rows, key=lambda x: cast(datetime, x["ts"]), reverse=True)
    return rows_sorted[offset : offset + limit], len(rows_sorted)


def test_list_decisions_filters_and_paging(monkeypatch):
    monkeypatch.setattr(dec, "_provider", _provider)
    app = _make_app()
    c = TestClient(app)

    r = c.get("/admin/api/decisions", params={"tenant": "t1", "page": 1, "page_size": 1})
    assert r.status_code == 200
    data = r.json()
    assert data["page"] == 1
    assert data["page_size"] == 1
    assert data["has_more"] is True
    assert data["total"] == 2
    assert data["items"][0]["tenant"] == "t1"

    r2 = c.get("/admin/api/decisions", params={"tenant": "t1", "page": 2, "page_size": 1})
    assert r2.status_code == 200
    d2 = r2.json()
    assert d2["page"] == 2
    assert d2["has_more"] is False


def test_since_filter(monkeypatch):
    monkeypatch.setattr(dec, "_provider", _provider)
    app = _make_app()
    c = TestClient(app)

    since = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat()
    r = c.get("/admin/api/decisions", params={"since": since})
    assert r.status_code == 200
    data = r.json()
    assert len(data["items"]) == 1
    assert data["items"][0]["id"] == "a3"

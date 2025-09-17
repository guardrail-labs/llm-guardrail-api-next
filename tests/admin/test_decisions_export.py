import csv
import io
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple, cast

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.routes import admin_decisions_api as dec


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(dec.router)
    return app


_items = [
    {
        "id": "a1",
        "ts": datetime.now(timezone.utc) - timedelta(minutes=5),
        "tenant": "t1",
        "bot": "b1",
        "outcome": "allow",
        "policy_version": "v1",
        "rule_id": None,
        "incident_id": None,
        "mode": "Tier1",
        "details": {"x": 1},
    },
    {
        "id": "a2",
        "ts": datetime.now(timezone.utc) - timedelta(minutes=3),
        "tenant": "t1",
        "bot": "b2",
        "outcome": "block_input_only",
        "policy_version": "v1",
        "rule_id": "r-secret",
        "incident_id": "inc-22",
        "mode": "Tier1",
        "details": {"why": "test"},
    },
    {
        "id": "a3",
        "ts": datetime.now(timezone.utc) - timedelta(minutes=1),
        "tenant": "t2",
        "bot": "b1",
        "outcome": "allow",
        "policy_version": "v2",
        "rule_id": None,
        "incident_id": None,
        "mode": "Tier2",
        "details": {},
    },
]


def _provider(
    since,
    tenant,
    bot,
    outcome,
    limit,
    offset,
) -> Tuple[List[Dict[str, Any]], Optional[int]]:
    rows = _items
    if since:
        rows = [x for x in rows if x["ts"] >= since]
    if tenant:
        rows = [x for x in rows if x.get("tenant") == tenant]
    if bot:
        rows = [x for x in rows if x.get("bot") == bot]
    if outcome:
        rows = [x for x in rows if x.get("outcome") == outcome]
    rows_sorted = sorted(rows, key=lambda x: cast(datetime, x["ts"]), reverse=True)
    # simple paging
    return rows_sorted[offset : offset + limit], len(rows_sorted)


def test_export_csv(monkeypatch):
    # Inject provider
    monkeypatch.setattr(dec, "_provider", _provider)
    app = _make_app()
    client = TestClient(app)

    response = client.get("/admin/api/decisions/export", params={"format": "csv"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    # Parse a few rows
    buf = io.StringIO(response.text)
    reader = csv.DictReader(buf)
    rows = list(reader)
    assert len(rows) == 3
    assert set(
        [
            "ts",
            "tenant",
            "bot",
            "outcome",
            "policy_version",
            "rule_id",
            "incident_id",
            "mode",
            "id",
            "details",
        ]
    ).issubset(reader.fieldnames or [])
    assert rows[0]["tenant"] in ("t1", "t2")


def test_export_jsonl(monkeypatch):
    monkeypatch.setattr(dec, "_provider", _provider)
    app = _make_app()
    client = TestClient(app)

    response = client.get("/admin/api/decisions/export", params={"format": "jsonl"})
    assert response.status_code == 200
    assert "application/x-ndjson" in response.headers["content-type"]
    lines = [ln for ln in response.text.strip().splitlines() if ln]
    assert len(lines) == 3
    obj = json.loads(lines[0])
    assert {"id", "ts", "tenant", "bot", "outcome"}.issubset(obj.keys())


def test_export_filters_apply(monkeypatch):
    monkeypatch.setattr(dec, "_provider", _provider)
    app = _make_app()
    client = TestClient(app)

    response = client.get(
        "/admin/api/decisions/export",
        params={"format": "jsonl", "tenant": "t1"},
    )
    assert response.status_code == 200
    lines = [ln for ln in response.text.strip().splitlines() if ln]
    assert len(lines) == 2
    for ln in lines:
        assert json.loads(ln)["tenant"] == "t1"

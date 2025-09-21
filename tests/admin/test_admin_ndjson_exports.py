from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture
def app_factory():
    def _factory():
        return create_app()

    return _factory


def test_decisions_export_headers_and_lines(app_factory, monkeypatch):
    from app.services import decisions_store as store

    base = 1_700_000_000_000
    items = [
        {"id": "a", "ts_ms": base + 2, "outcome": "block", "tenant": "t", "bot": "b"},
        {"id": "b", "ts_ms": base + 1, "outcome": "allow", "tenant": "t", "bot": "b"},
    ]

    monkeypatch.setattr(store, "_fetch_decisions_sorted_desc", lambda **_: items)

    client = TestClient(app_factory())
    response = client.get(
        f"/admin/api/decisions/export.ndjson?tenant=t&bot=b&since={base}&outcome=block"
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-ndjson")
    assert "attachment; filename=" in response.headers["content-disposition"].lower()
    lines = [line for line in response.text.splitlines() if line.strip()]
    assert len(lines) == 1 and '"id":"a"' in lines[0]


def test_adjudications_export_filters(app_factory):
    from app.observability import adjudication_log as log

    log.clear()

    def _record(ts_ms: int, rid: str, decision: str, hits=None):
        ts = (
            datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )
        return log.AdjudicationRecord(
            ts=ts,
            request_id=rid,
            tenant="t",
            bot="b",
            provider="p",
            decision=decision,
            rule_hits=hits or [],
            score=None,
            latency_ms=0,
            policy_version=None,
            rules_path=None,
            sampled=False,
            prompt_sha256=None,
        )

    base = 1_700_000_000_000
    log.append(_record(base + 2, "R1", "block", [{"rule_id": "X"}]))
    log.append(_record(base + 1, "R2", "allow", [{"rule_id": "Y"}]))

    client = TestClient(app_factory())
    response = client.get(
        f"/admin/api/adjudications/export.ndjson?tenant=t&bot=b&since={base}&outcome=block&rule_id=X"
    )

    assert response.status_code == 200
    lines = [line for line in response.text.splitlines() if line.strip()]
    assert len(lines) == 1 and '"request_id":"R1"' in lines[0]
    log.clear()

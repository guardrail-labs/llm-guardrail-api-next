from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Tuple
from urllib.parse import parse_qs, urlparse

import pytest
from starlette.testclient import TestClient

import app.observability.adjudication_log as adjudication_log
from app.main import create_app
from app.routes import admin_adjudications


@pytest.fixture()
def admin_client() -> Iterator[TestClient]:
    os.environ["ADMIN_UI_TOKEN"] = "secret"
    app = create_app()
    with TestClient(app) as client:
        yield client


def _auth_headers() -> Dict[str, str]:
    return {"Authorization": "Bearer secret"}


def _record(ts: datetime, rule_id: str | None = None) -> adjudication_log.AdjudicationRecord:
    rec = adjudication_log.AdjudicationRecord(
        ts=ts.isoformat(timespec="seconds").replace("+00:00", "Z"),
        request_id="req-1",
        tenant="tenant-1",
        bot="bot-1",
        provider="core",
        decision="block",
        rule_hits=["rule:block"],
        score=None,
        latency_ms=10,
        policy_version="v1",
        rules_path="pack/path",
        sampled=False,
        prompt_sha256=None,
    )
    if rule_id is not None:
        setattr(rec, "rule_id", rule_id)
    return rec


def _install_paged_query(
    monkeypatch: pytest.MonkeyPatch,
    records: List[adjudication_log.AdjudicationRecord],
    *,
    capture: Dict[str, Any] | None = None,
) -> None:
    def fake_paged_query(
        *,
        start: Any,
        end: Any,
        tenant: Any,
        bot: Any,
        provider: Any,
        request_id: Any,
        rule_id: Any,
        decision: Any,
        mitigation_forced: Any,
        limit: Any,
        offset: Any,
        sort: Any,
    ) -> Tuple[List[adjudication_log.AdjudicationRecord], int]:
        if capture is not None:
            capture.update(
                {
                    "start": start,
                    "end": end,
                    "tenant": tenant,
                    "bot": bot,
                    "provider": provider,
                    "request_id": request_id,
                    "rule_id": rule_id,
                    "decision": decision,
                    "mitigation_forced": mitigation_forced,
                    "limit": limit,
                    "offset": offset,
                    "sort": sort,
                }
            )
        return records, len(records)

    monkeypatch.setattr(admin_adjudications.adjudication_log, "paged_query", fake_paged_query)


def test_rule_id_input_renders(admin_client: TestClient) -> None:
    response = admin_client.get("/admin/ui/adjudications", headers=_auth_headers())
    assert response.status_code == 200
    assert 'id="filter-rule-id"' in response.text


def test_rule_id_filter_forwarded(
    monkeypatch: pytest.MonkeyPatch, admin_client: TestClient
) -> None:
    calls: Dict[str, Any] = {}
    record = _record(datetime(2024, 3, 1, tzinfo=timezone.utc), rule_id="r-42")
    _install_paged_query(monkeypatch, [record], capture=calls)

    response = admin_client.get(
        "/admin/ui/adjudications",
        headers=_auth_headers(),
        params={"rule_id": "r-42"},
    )
    assert response.status_code == 200
    assert calls["rule_id"] == "r-42"
    html = response.text
    assert 'name="rule_id" value="r-42"' in html


def test_rule_id_querystring_prefills(admin_client: TestClient) -> None:
    response = admin_client.get(
        "/admin/ui/adjudications",
        headers=_auth_headers(),
        params={"rule_id": "r-007"},
    )
    assert response.status_code == 200
    assert 'id="filter-rule-id" name="rule_id" value="r-007"' in response.text


def test_rule_id_included_in_ndjson_link(admin_client: TestClient) -> None:
    response = admin_client.get(
        "/admin/ui/adjudications",
        headers=_auth_headers(),
        params={"rule_id": "r-21"},
    )
    assert response.status_code == 200
    match = re.search(r'id="adjudications-download"[^>]*href="([^"]+)"', response.text)
    assert match is not None
    href = match.group(1)
    parsed = urlparse(href)
    assert parsed.path == "/admin/adjudications.ndjson"
    query = parse_qs(parsed.query)
    assert query.get("rule_id") == ["r-21"]
    assert query.get("sort") == ["ts_desc"]


def test_blank_rule_id_not_forwarded(
    monkeypatch: pytest.MonkeyPatch, admin_client: TestClient
) -> None:
    calls: Dict[str, Any] = {}
    record = _record(datetime(2024, 3, 2, tzinfo=timezone.utc), rule_id="r-1")
    _install_paged_query(monkeypatch, [record], capture=calls)

    response = admin_client.get(
        "/admin/ui/adjudications",
        headers=_auth_headers(),
        params={"rule_id": ""},
    )
    assert response.status_code == 200
    assert calls.get("rule_id") is None
    match = re.search(r'id="adjudications-download"[^>]*href="([^"]+)"', response.text)
    assert match is not None
    assert "rule_id=" not in match.group(1)

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Tuple

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


def _record(
    ts: datetime,
    *,
    tenant: str = "tenant-1",
    bot: str = "bot-1",
    decision: str = "block",
    mitigation: str | None = None,
    rules_path: str | None = "pack/path",
    rule_hit: str | None = "rule:hit",
    notes: str | None = None,
) -> adjudication_log.AdjudicationRecord:
    rec = adjudication_log.AdjudicationRecord(
        ts=ts.isoformat(timespec="seconds").replace("+00:00", "Z"),
        request_id="req-1",
        tenant=tenant,
        bot=bot,
        provider="core",
        decision=decision,
        rule_hits=[rule_hit] if rule_hit else [],
        score=None,
        latency_ms=10,
        policy_version="v1",
        rules_path=rules_path,
        sampled=False,
        prompt_sha256=None,
    )
    if mitigation is not None:
        setattr(rec, "mitigation_forced", mitigation)
    if notes is not None:
        setattr(rec, "notes", notes)
    return rec


def _install_paged_query(
    monkeypatch: pytest.MonkeyPatch,
    records: List[adjudication_log.AdjudicationRecord],
    *,
    total: int | None = None,
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
                    "decision": decision,
                    "mitigation_forced": mitigation_forced,
                    "limit": limit,
                    "offset": offset,
                    "sort": sort,
                }
            )
        return records, total if total is not None else len(records)

    monkeypatch.setattr(admin_adjudications.adjudication_log, "paged_query", fake_paged_query)


def test_controls_render(admin_client: TestClient) -> None:
    response = admin_client.get("/admin/ui/adjudications", headers=_auth_headers())
    assert response.status_code == 200
    html = response.text
    assert 'id="filter-tenant"' in html
    assert 'id="filter-bot"' in html
    assert 'id="filter-decision"' in html
    assert 'id="filter-mitigation"' in html
    assert 'id="filter-from"' in html
    assert 'id="filter-to"' in html
    assert 'id="filter-sort"' in html
    assert 'id="filter-limit" value="50"' in html
    assert 'id="adjudications-download"' in html
    assert 'Download NDJSON' in html


def test_filters_apply(monkeypatch: pytest.MonkeyPatch, admin_client: TestClient) -> None:
    calls: Dict[str, Any] = {}
    record = _record(
        datetime(2024, 3, 1, 12, 0, tzinfo=timezone.utc),
        tenant="t1",
        bot="b1",
        decision="block",
        mitigation="clarify",
        rule_hit="rule:block",
    )
    _install_paged_query(monkeypatch, [record], capture=calls)

    response = admin_client.get(
        "/admin/ui/adjudications",
        headers=_auth_headers(),
        params={"tenant": "t1", "decision": "block"},
    )
    assert response.status_code == 200
    assert calls["tenant"] == "t1"
    assert calls["decision"] == "block"
    html = response.text
    assert "pack/path / rule:block" in html
    assert "clarify" in html


def test_mitigation_filter(monkeypatch: pytest.MonkeyPatch, admin_client: TestClient) -> None:
    calls: Dict[str, Any] = {}
    record = _record(
        datetime(2024, 3, 2, 0, 0, tzinfo=timezone.utc),
        mitigation="clarify",
        rule_hit="rule:clarify",
    )
    _install_paged_query(monkeypatch, [record], capture=calls)

    response = admin_client.get(
        "/admin/ui/adjudications",
        headers=_auth_headers(),
        params={"mitigation_forced": "clarify"},
    )
    assert response.status_code == 200
    assert calls["mitigation_forced"] == "clarify"
    html = response.text
    assert "pack/path / rule:clarify" in html
    assert "clarify" in html


def test_pagination_slice(monkeypatch: pytest.MonkeyPatch, admin_client: TestClient) -> None:
    record = _record(
        datetime(2024, 3, 3, 0, 0, tzinfo=timezone.utc),
        rule_hit="rule:third",
    )
    capture: Dict[str, Any] = {}
    _install_paged_query(monkeypatch, [record], total=3, capture=capture)

    response = admin_client.get(
        "/admin/ui/adjudications",
        headers=_auth_headers(),
        params={"limit": "2", "offset": "2"},
    )
    assert response.status_code == 200
    assert capture["limit"] == 2
    assert capture["offset"] == 2
    html = response.text
    assert "rule:third" in html
    assert "Showing 3" in html


def test_sort_parameter_respected(
    monkeypatch: pytest.MonkeyPatch, admin_client: TestClient
) -> None:
    capture: Dict[str, Any] = {}
    record_one = _record(
        datetime(2024, 3, 1, 0, 0, tzinfo=timezone.utc),
        rule_hit="rule:first",
    )
    record_two = _record(
        datetime(2024, 3, 1, 0, 1, tzinfo=timezone.utc),
        rule_hit="rule:second",
    )
    _install_paged_query(monkeypatch, [record_one, record_two], capture=capture)

    response = admin_client.get(
        "/admin/ui/adjudications",
        headers=_auth_headers(),
        params={"sort": "ts_asc"},
    )
    assert response.status_code == 200
    assert capture["sort"] == "ts_asc"
    html = response.text
    assert html.index("rule:first") < html.index("rule:second")


def test_ndjson_link_honors_filters(
    monkeypatch: pytest.MonkeyPatch, admin_client: TestClient
) -> None:
    record = _record(datetime(2024, 3, 4, 0, 0, tzinfo=timezone.utc))
    _install_paged_query(monkeypatch, [record])

    response = admin_client.get(
        "/admin/ui/adjudications",
        headers=_auth_headers(),
        params={
            "tenant": "t1",
            "decision": "clarify",
            "sort": "ts_asc",
            "mitigation_forced": "redact",
            "limit": "100",
            "offset": "200",
        },
    )
    assert response.status_code == 200
    html = response.text
    match = re.search(r'id="adjudications-download"[^>]*href="([^"]+)"', html)
    assert match is not None
    href = match.group(1)
    assert href == (
        "/admin/adjudications.ndjson?tenant=t1&decision=clarify"
        "&mitigation_forced=redact&sort=ts_asc"
    )


def test_querystring_prefills_inputs(admin_client: TestClient) -> None:
    response = admin_client.get(
        "/admin/ui/adjudications",
        headers=_auth_headers(),
        params={
            "tenant": "tenant-x",
            "bot": "bot-y",
            "decision": "allow",
            "mitigation_forced": "block",
        },
    )
    assert response.status_code == 200
    html = response.text
    assert 'id="filter-tenant" name="tenant" value="tenant-x"' in html
    assert 'id="filter-bot" name="bot" value="bot-y"' in html
    assert 'option value="allow" selected' in html
    assert 'option value="block" selected' in html

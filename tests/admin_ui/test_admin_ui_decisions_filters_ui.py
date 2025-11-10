from __future__ import annotations

import os
import re
from typing import Any, Dict, Iterator, List

import pytest
from starlette.testclient import TestClient

from app.main import create_app
from app.routes import admin_decisions


@pytest.fixture()
def admin_client() -> Iterator[TestClient]:
    os.environ["ADMIN_UI_TOKEN"] = "secret"
    app = create_app()
    with TestClient(app) as client:
        yield client


def _auth_headers() -> Dict[str, str]:
    return {"Authorization": "Bearer secret"}


def test_controls_render(admin_client: TestClient) -> None:
    response = admin_client.get("/admin/ui/decisions", headers=_auth_headers())
    assert response.status_code == 200
    html = response.text
    assert 'id="filter-tenant"' in html
    assert 'id="filter-bot"' in html
    assert 'id="filter-rule-id"' in html
    assert 'id="filter-decision"' in html
    assert 'id="filter-from"' in html
    assert 'id="filter-to"' in html
    assert 'id="filter-sort"' in html
    assert 'id="filter-limit" value="50"' in html
    assert 'id="decisions-download"' in html
    assert "Download NDJSON" in html


def test_filters_apply(monkeypatch: pytest.MonkeyPatch, admin_client: TestClient) -> None:
    calls: Dict[str, Any] = {}

    def fake_list_decisions(**kwargs: Any) -> List[Dict[str, Any]]:
        calls.update(kwargs)
        return [
            {
                "ts": 1710000000,
                "tenant": "t1",
                "bot": "b1",
                "decision": "block",
                "rule_id": "r-1",
                "mitigation_forced": "clarify",
                "summary": "Blocked request",
            }
        ]

    monkeypatch.setattr(admin_decisions, "list_decisions", fake_list_decisions)

    response = admin_client.get(
        "/admin/ui/decisions",
        headers=_auth_headers(),
        params={"tenant": "t1", "decision": "block"},
    )
    assert response.status_code == 200
    assert calls["tenant"] == "t1"
    assert calls["decision"] == "block"
    html = response.text
    assert "Blocked request" in html
    assert "clarify" in html


def test_pagination_slice(monkeypatch: pytest.MonkeyPatch, admin_client: TestClient) -> None:
    def fake_list_decisions(**_: Any) -> List[Dict[str, Any]]:
        return [
            {"ts": 100, "summary": "row-1"},
            {"ts": 101, "summary": "row-2"},
            {"ts": 102, "summary": "row-3"},
        ]

    monkeypatch.setattr(admin_decisions, "list_decisions", fake_list_decisions)

    response = admin_client.get(
        "/admin/ui/decisions",
        headers=_auth_headers(),
        params={"limit": "2", "offset": "2"},
    )
    assert response.status_code == 200
    html = response.text
    assert "row-3" in html
    assert "row-1" not in html
    assert "Showing 3" in html


def test_sort_parameter_respected(
    monkeypatch: pytest.MonkeyPatch, admin_client: TestClient
) -> None:
    captured: Dict[str, Any] = {}

    def fake_list_decisions(**kwargs: Any) -> List[Dict[str, Any]]:
        captured.update(kwargs)
        return [{"ts": 1, "summary": "first"}, {"ts": 2, "summary": "second"}]

    monkeypatch.setattr(admin_decisions, "list_decisions", fake_list_decisions)

    response = admin_client.get(
        "/admin/ui/decisions",
        headers=_auth_headers(),
        params={"sort": "ts_asc"},
    )
    assert response.status_code == 200
    assert captured["sort"] == "ts_asc"
    html = response.text
    assert html.index("first") < html.index("second")


def test_ndjson_link_honors_filters(
    monkeypatch: pytest.MonkeyPatch, admin_client: TestClient
) -> None:
    def fake_list_decisions(**_: Any) -> List[Dict[str, Any]]:
        return []

    monkeypatch.setattr(admin_decisions, "list_decisions", fake_list_decisions)

    response = admin_client.get(
        "/admin/ui/decisions",
        headers=_auth_headers(),
        params={"tenant": "t1", "decision": "clarify", "sort": "ts_asc"},
    )
    assert response.status_code == 200
    html = response.text
    match = re.search(r'id="decisions-download"[^>]*href="([^"]+)"', html)
    assert match is not None
    href = match.group(1)
    assert href == "/admin/decisions.ndjson?tenant=t1&decision=clarify&sort=ts_asc"


def test_querystring_prefills_inputs(admin_client: TestClient) -> None:
    response = admin_client.get(
        "/admin/ui/decisions",
        headers=_auth_headers(),
        params={"tenant": "t-42", "decision": "clarify"},
    )
    assert response.status_code == 200
    html = response.text
    assert 'id="filter-tenant" name="tenant" value="t-42"' in html
    decision_match = re.search(r'id="filter-decision"[^>]*>\s*<option value=""[^<]*</option>', html)
    assert decision_match is not None
    assert 'option value="clarify" selected' in html

import json
import os
from typing import Any, Dict, Iterator, cast
from urllib.parse import parse_qs, urlparse

import pytest
from bs4 import BeautifulSoup
from starlette.testclient import TestClient

from app.main import create_app
from app.routes import admin_adjudications, admin_decisions


@pytest.fixture()
def admin_client() -> Iterator[TestClient]:
    os.environ["ADMIN_UI_TOKEN"] = "secret"
    app = create_app()
    with TestClient(app) as client:
        yield client


def _auth_headers() -> Dict[str, str]:
    return {"Authorization": "Bearer secret"}


def test_decisions_cross_links_and_json_modal(
    monkeypatch: pytest.MonkeyPatch, admin_client: TestClient
) -> None:
    sample_item: Dict[str, Any] = {
        "ts": 1_710_000_000,
        "tenant": "tenant-x",
        "bot": "bot-y",
        "decision": "allow",
        "rule_id": "rule-42",
        "mitigation_forced": "",
        "request_id": "abc123",
        "message": "<script>alert(1)</script>",
        "details": {"prompt": "prompt"},
    }

    def fake_list_decisions(**kwargs: Any) -> list[dict[str, Any]]:
        return [sample_item]

    monkeypatch.setattr(admin_decisions, "list_decisions", fake_list_decisions)

    response = admin_client.get(
        "/admin/ui/decisions",
        headers=_auth_headers(),
        params={"tenant": "tenant-x", "bot": "bot-y"},
    )
    assert response.status_code == 200
    html = response.text
    soup = BeautifulSoup(html, "html.parser")

    row = soup.select_one("#decisions-tbody tr")
    assert row is not None
    request_cell = row.select_one("td.reqid-cell")
    assert request_cell is not None

    primary = request_cell.select_one("a.reqid-primary")
    filter_link = request_cell.select_one("a.reqid-filter")
    assert primary is not None
    assert filter_link is not None

    primary_href = cast(str, primary.get("href"))
    assert primary_href
    primary_url = urlparse(primary_href)
    primary_query = parse_qs(primary_url.query)
    assert primary_url.path == "/admin/adjudications"
    assert primary_query.get("request_id") == ["abc123"]
    assert primary_query.get("tenant") == ["tenant-x"]
    assert primary_query.get("bot") == ["bot-y"]
    assert "offset" not in primary_query
    assert "limit" not in primary_query

    filter_href = cast(str, filter_link.get("href"))
    assert filter_href
    filter_url = urlparse(filter_href)
    filter_query = parse_qs(filter_url.query)
    assert filter_url.path == "/admin/decisions"
    assert filter_query.get("request_id") == ["abc123"]
    assert filter_query.get("tenant") == ["tenant-x"]
    assert filter_query.get("bot") == ["bot-y"]

    button = row.select_one("td.row-actions button.view-json-btn")
    assert button is not None
    data_json = cast(str, button.get("data-json"))
    assert data_json
    parsed = json.loads(data_json)
    assert parsed["request_id"] == "abc123"
    assert parsed["message"] == "<script>alert(1)</script>"

    modal_pre = soup.select_one("#decisions-json-modal-content")
    assert modal_pre is not None
    assert "jsonModalContent.textContent = pretty;" in html
    assert "navigator.clipboard.writeText" in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html or "\\u003cscript" in html


class _FakeRecord:
    def __init__(self, payload: Dict[str, Any]) -> None:
        self._payload = payload

    def to_dict(self) -> Dict[str, Any]:
        return dict(self._payload)


def test_adjudications_cross_links_and_json_modal(
    monkeypatch: pytest.MonkeyPatch, admin_client: TestClient
) -> None:
    sample_record = {
        "ts": 1_720_000_000,
        "tenant": "tenant-x",
        "bot": "bot-y",
        "decision": "block",
        "mitigation_forced": "clarify",
        "request_id": "req-789",
        "rule_hits": ["rule-1"],
        "rules_path": "pack/path",
        "notes": "<script>n</script>",
    }

    def fake_paged_query(**kwargs: Any) -> tuple[list[_FakeRecord], int]:
        return [_FakeRecord(sample_record)], 1

    monkeypatch.setattr(
        admin_adjudications.adjudication_log,
        "paged_query",
        fake_paged_query,
    )

    response = admin_client.get(
        "/admin/ui/adjudications",
        headers=_auth_headers(),
        params={"tenant": "tenant-x", "bot": "bot-y"},
    )
    assert response.status_code == 200
    html = response.text
    soup = BeautifulSoup(html, "html.parser")

    row = soup.select_one("#adjudications-tbody tr")
    assert row is not None
    request_cell = row.select_one("td.reqid-cell")
    assert request_cell is not None

    primary = request_cell.select_one("a.reqid-primary")
    filter_link = request_cell.select_one("a.reqid-filter")
    assert primary is not None
    assert filter_link is not None

    primary_href = cast(str, primary.get("href"))
    assert primary_href
    primary_url = urlparse(primary_href)
    primary_query = parse_qs(primary_url.query)
    assert primary_url.path == "/admin/decisions"
    assert primary_query.get("request_id") == ["req-789"]
    assert primary_query.get("tenant") == ["tenant-x"]
    assert primary_query.get("bot") == ["bot-y"]

    filter_href = cast(str, filter_link.get("href"))
    assert filter_href
    filter_url = urlparse(filter_href)
    filter_query = parse_qs(filter_url.query)
    assert filter_url.path == "/admin/adjudications"
    assert filter_query.get("request_id") == ["req-789"]

    button = row.select_one("td.row-actions button.view-json-btn")
    assert button is not None
    data_json = cast(str, button.get("data-json"))
    assert data_json
    parsed = json.loads(data_json)
    assert parsed["request_id"] == "req-789"
    assert parsed["notes"] == "<script>n</script>"
    assert "&lt;script&gt;n&lt;/script&gt;" in html or "\\u003cscript" in html


def test_decisions_ndjson_link_includes_request(
    monkeypatch: pytest.MonkeyPatch, admin_client: TestClient
) -> None:
    def fake_list_decisions(**kwargs: Any) -> list[dict[str, Any]]:
        return []

    monkeypatch.setattr(admin_decisions, "list_decisions", fake_list_decisions)

    response = admin_client.get(
        "/admin/ui/decisions",
        headers=_auth_headers(),
        params={"request_id": "abc123", "limit": "200", "offset": "40"},
    )
    assert response.status_code == 200
    soup = BeautifulSoup(response.text, "html.parser")
    download = soup.select_one("#decisions-download")
    assert download is not None
    href = cast(str, download.get("href"))
    assert href
    parsed = urlparse(href)
    query = parse_qs(parsed.query)
    assert query.get("request_id") == ["abc123"]
    assert "offset" not in query
    assert "limit" not in query

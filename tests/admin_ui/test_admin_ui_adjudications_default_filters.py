from __future__ import annotations

import os
from html.parser import HTMLParser
from typing import Any, Dict, Iterator

import pytest
from starlette.testclient import TestClient

from app.main import create_app
from app.routes import admin_adjudications


class _DownloadLinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.href: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        attr_map = dict(attrs)
        if attr_map.get("id") == "adjudications-download":
            self.href = attr_map.get("href")


@pytest.fixture()
def admin_client() -> Iterator[TestClient]:
    os.environ["ADMIN_UI_TOKEN"] = "secret"
    app = create_app()
    with TestClient(app) as client:
        yield client


def _auth_headers() -> Dict[str, str]:
    return {"Authorization": "Bearer secret"}


def _install_fake_paged_query(
    monkeypatch: pytest.MonkeyPatch, capture: Dict[str, Any]
) -> None:
    def fake_paged_query(**kwargs: Any) -> tuple[list[Any], int]:
        capture.update(kwargs)
        return [], 0

    monkeypatch.setattr(admin_adjudications.adjudication_log, "paged_query", fake_paged_query)


def test_default_view_does_not_filter_by_blank_values(
    monkeypatch: pytest.MonkeyPatch, admin_client: TestClient
) -> None:
    calls: Dict[str, Any] = {}
    _install_fake_paged_query(monkeypatch, calls)

    response = admin_client.get("/admin/ui/adjudications", headers=_auth_headers())

    assert response.status_code == 200
    assert calls["mitigation_forced"] is None
    assert calls.get("decision") is None
    assert calls.get("rule_id") is None


def test_blank_controls_do_not_emit_query_params(admin_client: TestClient) -> None:
    response = admin_client.get(
        "/admin/ui/adjudications",
        headers=_auth_headers(),
        params={"tenant": "tenant-1", "limit": "25"},
    )

    assert response.status_code == 200

    parser = _DownloadLinkParser()
    parser.feed(response.text)
    href = parser.href or ""

    assert "mitigation_forced=" not in href
    assert "decision=" not in href
    assert "rule_id=" not in href


def test_non_blank_values_are_forwarded(
    monkeypatch: pytest.MonkeyPatch, admin_client: TestClient
) -> None:
    calls: Dict[str, Any] = {}
    _install_fake_paged_query(monkeypatch, calls)

    response = admin_client.get(
        "/admin/ui/adjudications",
        headers=_auth_headers(),
        params={"mitigation_forced": "clarify", "decision": "block", "rule_id": "r-9"},
    )

    assert response.status_code == 200
    assert calls["mitigation_forced"] == "clarify"
    assert calls["decision"] == "block"
    assert calls["rule_id"] == "r-9"

from __future__ import annotations

import os
import re
from typing import Any, Dict, Iterator

import pytest
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


def test_request_id_inputs_render(admin_client: TestClient) -> None:
    decisions_page = admin_client.get("/admin/ui/decisions", headers=_auth_headers())
    assert decisions_page.status_code == 200
    assert 'id="filter-request-id"' in decisions_page.text
    assert 'name="request_id"' in decisions_page.text

    adjudications_page = admin_client.get("/admin/ui/adjudications", headers=_auth_headers())
    assert adjudications_page.status_code == 200
    assert 'id="filter-request-id"' in adjudications_page.text
    assert 'name="request_id"' in adjudications_page.text


def test_decisions_request_id_filtering(
    monkeypatch: pytest.MonkeyPatch, admin_client: TestClient
) -> None:
    captured: Dict[str, Any] = {}

    def fake_list_decisions(**kwargs: Any) -> list[dict[str, Any]]:
        captured.update(kwargs)
        return []

    monkeypatch.setattr(admin_decisions, "list_decisions", fake_list_decisions)

    response = admin_client.get(
        "/admin/ui/decisions",
        headers=_auth_headers(),
        params={"request_id": "abc123", "sort": "ts_asc"},
    )
    assert response.status_code == 200
    assert captured["request_id"] == "abc123"
    html = response.text
    assert 'id="filter-request-id" name="request_id" value="abc123"' in html
    link = re.search(r'id="decisions-download"[^>]*href="([^"]+)"', html)
    assert link is not None
    href = link.group(1)
    assert "request_id=abc123" in href


def test_decisions_request_id_blank_omitted(
    monkeypatch: pytest.MonkeyPatch, admin_client: TestClient
) -> None:
    captured: Dict[str, Any] = {}

    def fake_list_decisions(**kwargs: Any) -> list[dict[str, Any]]:
        captured.update(kwargs)
        return []

    monkeypatch.setattr(admin_decisions, "list_decisions", fake_list_decisions)

    response = admin_client.get(
        "/admin/ui/decisions",
        headers=_auth_headers(),
        params={"request_id": ""},
    )
    assert response.status_code == 200
    assert captured.get("request_id") is None
    link = re.search(r'id="decisions-download"[^>]*href="([^"]+)"', response.text)
    assert link is not None
    assert "request_id=" not in link.group(1)


def test_adjudications_request_id_filtering(
    monkeypatch: pytest.MonkeyPatch, admin_client: TestClient
) -> None:
    captured: Dict[str, Any] = {}

    def fake_paged_query(**kwargs: Any) -> tuple[list[dict[str, Any]], int]:
        captured.update(kwargs)
        return [], 0

    monkeypatch.setattr(
        admin_adjudications.adjudication_log,
        "paged_query",
        fake_paged_query,
    )

    response = admin_client.get(
        "/admin/ui/adjudications",
        headers=_auth_headers(),
        params={"request_id": "xyz-789"},
    )
    assert response.status_code == 200
    assert captured["request_id"] == "xyz-789"
    html = response.text
    assert 'id="filter-request-id" name="request_id" value="xyz-789"' in html
    link = re.search(r'id="adjudications-download"[^>]*href="([^"]+)"', html)
    assert link is not None
    href = link.group(1)
    assert "request_id=xyz-789" in href


def test_adjudications_request_id_blank_omitted(
    monkeypatch: pytest.MonkeyPatch, admin_client: TestClient
) -> None:
    captured: Dict[str, Any] = {}

    def fake_paged_query(**kwargs: Any) -> tuple[list[dict[str, Any]], int]:
        captured.update(kwargs)
        return [], 0

    monkeypatch.setattr(
        admin_adjudications.adjudication_log,
        "paged_query",
        fake_paged_query,
    )

    response = admin_client.get(
        "/admin/ui/adjudications",
        headers=_auth_headers(),
        params={"request_id": ""},
    )
    assert response.status_code == 200
    assert captured.get("request_id") is None
    link = re.search(r'id="adjudications-download"[^>]*href="([^"]+)"', response.text)
    assert link is not None
    assert "request_id=" not in link.group(1)

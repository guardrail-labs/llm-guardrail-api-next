from __future__ import annotations

import os
from typing import Any, Dict, Iterable, List

import pytest
from bs4 import BeautifulSoup
from starlette.testclient import TestClient

from app.main import create_app
from app.routes.admin_ui import templates


@pytest.fixture()
def admin_client() -> Iterable[TestClient]:
    os.environ["ADMIN_UI_TOKEN"] = "secret"
    app = create_app()
    with TestClient(app) as client:
        yield client


def _auth_headers() -> Dict[str, str]:
    return {"Authorization": "Bearer secret"}


def _render_policy_with_lints(lints: List[Dict[str, Any]]) -> str:
    template = templates.env.get_template("policy.html")
    context = {
        "request": object(),
        "csrf_token": "csrf-123",
        "version": "v-test",
        "packs": ["pack-a"],
        "lints": lints,
    }
    return template.render(context)


def test_badges_render_by_severity() -> None:
    html = _render_policy_with_lints(
        [
            {
                "severity": "error",
                "message": "Policy error message",
                "rule_id": "error-rule",
                "code": "E100",
                "path": "$.error.path",
                "line": 7,
                "column": 9,
            },
            {
                "severity": "warn",
                "message": "Policy warn message",
                "ruleId": "warn-rule",
                "id": "W200",
                "pointer": "$.warn.path",
                "line_number": 3,
            },
            {
                "severity": "info",
                "message": "Policy info message",
                "code": "I300",
            },
        ]
    )
    soup = BeautifulSoup(html, "html.parser")
    rows = soup.select("#lints-list .lint-row")
    assert len(rows) == 3

    badge_text = [
        badge.text.strip() for badge in soup.select("#lints-list .lint-row span.lint-badge")
    ]
    assert badge_text == ["ERROR", "WARNING", "INFO"]

    first_meta_el = rows[0].select_one(".lint-meta")
    assert first_meta_el is not None
    first_meta = first_meta_el.text
    assert "Path:" in first_meta
    assert "Position:" in first_meta


def test_filter_toggles_hide_and_show_rows() -> None:
    html = _render_policy_with_lints(
        [
            {"severity": "error", "message": "Error lint"},
            {"severity": "warn", "message": "Warn lint"},
            {"severity": "info", "message": "Info lint"},
        ]
    )
    soup = BeautifulSoup(html, "html.parser")
    rows = soup.select("#lints-list .lint-row")
    severities = [str(row["data-severity"]) for row in rows]
    assert severities == ["error", "warn", "info"]

    filters = {"error": True, "warn": True, "info": True}

    def _visible(filter_state: Dict[str, bool]) -> List[str]:
        return [sev for sev in severities if filter_state.get(sev, False)]

    assert _visible(filters) == ["error", "warn", "info"]

    filters["warn"] = False
    assert _visible(filters) == ["error", "info"]

    filters["warn"] = True
    assert _visible(filters) == ["error", "warn", "info"]

    toolbar = soup.select_one(".lint-toolbar")
    assert toolbar is not None
    for key in ("error", "warn", "info"):
        button = toolbar.select_one(f"#filter-{key}")
        assert button is not None
        assert button.get("aria-pressed") == "true"


def test_copy_json_respects_filters(admin_client: TestClient) -> None:
    response = admin_client.get("/admin/policy", headers=_auth_headers())
    assert response.status_code == 200
    html = response.text

    assert "function getFilteredLints()" in html
    assert "const filtered = getFilteredLints()" in html
    assert "JSON.stringify(filtered)" in html
    assert "Copied ${filtered.length} lints" in html
    assert "Copy failed" in html

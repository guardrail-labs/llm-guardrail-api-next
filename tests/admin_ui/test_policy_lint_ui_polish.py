import os

from starlette.testclient import TestClient

from app.main import create_app


def _client() -> TestClient:
    os.environ["ADMIN_UI_TOKEN"] = "secret"
    app = create_app()
    return TestClient(app)


def _policy_html() -> str:
    client = _client()
    resp = client.get("/admin/policy", headers={"Authorization": "Bearer secret"})
    assert resp.status_code == 200
    return resp.text


def test_policy_lints_render_with_badges() -> None:
    html = _policy_html()
    assert "lint-badge lint-badge-error" in html
    assert "lint-badge lint-badge-warn" in html
    assert "lint-badge lint-badge-info" in html


def test_policy_lints_filters_default_active() -> None:
    html = _policy_html()
    assert 'id="filter-error" class="lint-filter-btn" type="button" aria-pressed="true"' in html
    assert 'id="filter-warn" class="lint-filter-btn" type="button" aria-pressed="true"' in html
    assert 'id="filter-info" class="lint-filter-btn" type="button" aria-pressed="true"' in html
    assert "lintState.filters" in html
    assert "No lints match the selected filters." in html


def test_policy_lints_copy_button_has_json_hook() -> None:
    html = _policy_html()
    assert "Copy as JSON" in html
    assert "copy-lints-json" in html
    assert "JSON.stringify(lintState.items, null, 2)" in html
    assert "Lints copied" in html


def test_policy_lints_empty_state_message() -> None:
    html = _policy_html()
    assert "No lints found." in html

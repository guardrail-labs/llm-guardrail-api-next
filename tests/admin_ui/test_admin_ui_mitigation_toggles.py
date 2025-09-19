from __future__ import annotations

from pathlib import Path
from typing import Iterator

import pytest
from starlette.testclient import TestClient

from app.main import create_app
from app.services import config_store, mitigation_modes


@pytest.fixture()
def admin_client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[TestClient]:
    mitigation_modes._reset_for_tests()
    cfg_dir = tmp_path / "config"
    bindings_path = cfg_dir / "bindings.yaml"
    admin_cfg_path = cfg_dir / "admin_config.yaml"
    monkeypatch.setattr(config_store, "_CONFIG_DIR", cfg_dir)
    monkeypatch.setattr(config_store, "_CONFIG_PATH", bindings_path)
    monkeypatch.setattr(config_store, "_ADMIN_CONFIG_PATH", admin_cfg_path)
    config_store.save_bindings([])

    from app import main as main_mod

    main_mod._BINDINGS.clear()

    monkeypatch.setenv("ADMIN_UI_TOKEN", "secret")
    monkeypatch.setenv("ADMIN_UI_AUTH", "1")
    monkeypatch.setenv("ADMIN_ENABLE_APPLY", "1")
    monkeypatch.setenv("API_KEY", "k")

    app = create_app()
    client = TestClient(app)
    try:
        yield client
    finally:
        main_mod._BINDINGS.clear()


def _auth_headers() -> dict[str, str]:
    return {"Authorization": "Bearer secret"}


def _checkbox_checked(html: str, element_id: str) -> bool:
    marker = f'id="{element_id}"'
    idx = html.find(marker)
    assert idx != -1, f"checkbox {element_id} missing"
    end = html.find('>', idx)
    if end == -1:
        end = len(html)
    snippet = html[idx:end]
    return "checked" in snippet


def test_mitigation_toggles_render_current_modes(admin_client: TestClient) -> None:
    tenant = "acme"
    bot = "support"
    payload = {
        "tenant": tenant,
        "bot": bot,
        "modes": {"block": True, "redact": False, "clarify_first": False},
    }
    save_resp = admin_client.put(
        "/admin/mitigation_modes", headers=_auth_headers(), json=payload
    )
    assert save_resp.status_code == 200

    page = admin_client.get(
        f"/admin/ui/bindings?tenant={tenant}&bot={bot}", headers=_auth_headers()
    )
    assert page.status_code == 200
    html = page.text
    assert _checkbox_checked(html, "mitigation-mode-block") is True
    assert _checkbox_checked(html, "mitigation-mode-redact") is False
    assert _checkbox_checked(html, "mitigation-mode-clarify") is False


def test_mitigation_toggle_save_flow(admin_client: TestClient) -> None:
    tenant = "toggle"
    bot = "bot"
    payload = {
        "tenant": tenant,
        "bot": bot,
        "modes": {"block": True, "redact": False, "clarify_first": False},
    }
    save_resp = admin_client.put(
        "/admin/mitigation_modes", headers=_auth_headers(), json=payload
    )
    assert save_resp.status_code == 200
    follow = admin_client.get(
        "/admin/mitigation_modes",
        headers=_auth_headers(),
        params={"tenant": tenant, "bot": bot},
    )
    assert follow.status_code == 200
    assert follow.json()["modes"]["block"] is True

    page = admin_client.get(
        f"/admin/ui/bindings?tenant={tenant}&bot={bot}", headers=_auth_headers()
    )
    assert page.status_code == 200
    assert "Saved mitigation modes for " in page.text


def test_mitigation_block_effect(admin_client: TestClient) -> None:
    tenant = "blocky"
    bot = "bot"
    payload = {
        "tenant": tenant,
        "bot": bot,
        "modes": {"block": True, "redact": False, "clarify_first": False},
    }
    save_resp = admin_client.put(
        "/admin/mitigation_modes", headers=_auth_headers(), json=payload
    )
    assert save_resp.status_code == 200

    headers = {
        "X-API-Key": "k",
        "X-Tenant-ID": tenant,
        "X-Bot-ID": bot,
    }
    resp = admin_client.post(
        "/v1/guardrail",
        json={"prompt": "hello"},
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "block"
    assert data["mitigation_modes"]["block"] is True


def test_mitigation_error_banner_surfaces_detail(admin_client: TestClient) -> None:
    tenant = "err"
    bot = "bot"
    bad = {
        "tenant": tenant,
        "bot": bot,
        "modes": {"block": "yes"},
    }
    error_resp = admin_client.put(
        "/admin/mitigation_modes", headers=_auth_headers(), json=bad
    )
    assert error_resp.status_code == 400
    detail = error_resp.json()["error"]
    assert detail

    page = admin_client.get(
        f"/admin/ui/bindings?tenant={tenant}&bot={bot}", headers=_auth_headers()
    )
    assert page.status_code == 200
    html = page.text
    assert 'id="mitigation-error"' in html
    assert "Failed to save mitigation modes." in html
    assert "Failed to load mitigation modes." in html
    assert "detail || result.body.error || result.body.message" in html

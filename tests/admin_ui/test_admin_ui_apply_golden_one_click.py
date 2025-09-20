from __future__ import annotations

from pathlib import Path
from typing import Any, Iterator

import pytest
from fastapi.testclient import TestClient
from pytest import MonkeyPatch

import app.routes.admin_ui as admin_ui_mod
from app.main import create_app
from app.services import config_store


@pytest.fixture()
def admin_client(monkeypatch: MonkeyPatch, tmp_path: Path) -> Iterator[TestClient]:
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

    app = create_app()
    client = TestClient(app)
    try:
        yield client
    finally:
        main_mod._BINDINGS.clear()


def _auth_headers() -> dict[str, str]:
    return {"Authorization": "Bearer secret"}


def _golden_button_snippet(html: str) -> str:
    marker = 'id="apply-golden-button"'
    idx = html.find(marker)
    assert idx != -1, "apply golden button missing"
    start = html.rfind('<button', 0, idx)
    end = html.find('</button>', idx)
    if start == -1 or end == -1:
        return html[idx: idx + 64]
    return html[start:end]


def test_button_hidden_without_flag(admin_client: TestClient) -> None:
    resp = admin_client.get("/admin/ui/bindings", headers=_auth_headers())
    assert resp.status_code == 200
    assert 'id="apply-golden-button"' not in resp.text


def test_button_visible_with_flag(
    admin_client: TestClient, monkeypatch: MonkeyPatch
) -> None:
    monkeypatch.setenv("ADMIN_ENABLE_GOLDEN_ONE_CLICK", "1")
    resp = admin_client.get("/admin/ui/bindings", headers=_auth_headers())
    assert resp.status_code == 200
    assert 'id="apply-golden-button"' in resp.text


def test_button_disabled_without_context(
    admin_client: TestClient, monkeypatch: MonkeyPatch
) -> None:
    monkeypatch.setenv("ADMIN_ENABLE_GOLDEN_ONE_CLICK", "1")
    resp = admin_client.get("/admin/ui/bindings", headers=_auth_headers())
    assert resp.status_code == 200
    snippet = _golden_button_snippet(resp.text)
    assert "disabled" in snippet


def test_button_enabled_with_context(
    admin_client: TestClient, monkeypatch: MonkeyPatch
) -> None:
    monkeypatch.setenv("ADMIN_ENABLE_GOLDEN_ONE_CLICK", "1")
    resp = admin_client.get(
        "/admin/ui/bindings?tenant=ten&bot=bot", headers=_auth_headers()
    )
    assert resp.status_code == 200
    snippet = _golden_button_snippet(resp.text)
    assert "disabled" not in snippet


def test_template_copies_cover_statuses(
    admin_client: TestClient, monkeypatch: MonkeyPatch
) -> None:
    monkeypatch.setenv("ADMIN_ENABLE_GOLDEN_ONE_CLICK", "1")
    resp = admin_client.get(
        "/admin/ui/bindings?tenant=acme&bot=support", headers=_auth_headers()
    )
    assert resp.status_code == 200
    html = resp.text
    assert "Refreshed Golden Packs" in html
    assert "Already up-to-date for" in html
    assert "Failed to apply Golden Packs." in html
    assert "csrf_token: getCookie('ui_csrf')" in html
    assert "applied: " in html


def test_apply_golden_happy_path(
    admin_client: TestClient, monkeypatch: MonkeyPatch
) -> None:
    monkeypatch.setenv("ADMIN_ENABLE_GOLDEN_ONE_CLICK", "1")

    captured: dict[str, dict[str, str]] = {}

    def fake_apply(payload: dict[str, str]) -> dict[str, Any]:
        captured["payload"] = payload
        return {
            "tenant": "t1",
            "bot": "b1",
            "rules_path": "/policies/golden.yaml",
            "version": "v123",
            "policy_version": "pol-9",
            "applied": True,
        }

    monkeypatch.setattr(admin_ui_mod, "apply_golden_action", fake_apply)
    monkeypatch.setattr(
        admin_ui_mod,
        "list_bindings",
        lambda: [{"tenant": "t1", "bot": "b1", "policy_version": "pol-9"}],
    )

    page = admin_client.get(
        "/admin/ui/bindings?tenant=t1&bot=b1", headers=_auth_headers()
    )
    csrf = page.cookies.get("ui_csrf")
    assert csrf

    resp = admin_client.post(
        "/admin/ui/bindings/apply_golden",
        headers=_auth_headers(),
        json={"tenant": "t1", "bot": "b1", "csrf_token": csrf},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert captured["payload"] == {"tenant": "t1", "bot": "b1"}
    assert body["status"] == "success"
    binding = body["binding"]
    assert binding["applied"] is True
    assert binding["rules_path"] == "/policies/golden.yaml"
    assert binding["version"] == "v123"
    assert binding["policy_version"] == "pol-9"
    assert any(b["policy_version"] == "pol-9" for b in body["bindings"])


def test_apply_golden_refresh_flow(
    admin_client: TestClient, monkeypatch: MonkeyPatch
) -> None:
    monkeypatch.setenv("ADMIN_ENABLE_GOLDEN_ONE_CLICK", "1")

    def fake_apply(payload: dict[str, str]) -> dict[str, Any]:
        return {
            "tenant": payload["tenant"],
            "bot": payload["bot"],
            "rules_path": "/policies/golden.yaml",
            "version": "v124",
            "policy_version": "pol-10",
            "applied": False,
        }

    monkeypatch.setattr(admin_ui_mod, "apply_golden_action", fake_apply)
    monkeypatch.setattr(
        admin_ui_mod,
        "list_bindings",
        lambda: [{"tenant": "acme", "bot": "bot", "policy_version": "pol-10"}],
    )

    page = admin_client.get(
        "/admin/ui/bindings?tenant=acme&bot=bot", headers=_auth_headers()
    )
    csrf = page.cookies.get("ui_csrf")
    assert csrf

    resp = admin_client.post(
        "/admin/ui/bindings/apply_golden",
        headers=_auth_headers(),
        json={"tenant": "acme", "bot": "bot", "csrf_token": csrf},
    )
    assert resp.status_code == 200
    body = resp.json()
    binding = body["binding"]
    assert binding["applied"] is False
    assert binding["version"] == "v124"
    assert binding["policy_version"] == "pol-10"
    assert binding["rules_path"] == "/policies/golden.yaml"


def test_apply_golden_error_surface(
    admin_client: TestClient, monkeypatch: MonkeyPatch
) -> None:
    monkeypatch.setenv("ADMIN_ENABLE_GOLDEN_ONE_CLICK", "1")

    def fake_apply(payload: dict[str, str]) -> dict[str, str]:
        raise ValueError("boom")

    monkeypatch.setattr(admin_ui_mod, "apply_golden_action", fake_apply)

    page = admin_client.get(
        "/admin/ui/bindings?tenant=acme&bot=bot", headers=_auth_headers()
    )
    csrf = page.cookies.get("ui_csrf")
    assert csrf

    resp = admin_client.post(
        "/admin/ui/bindings/apply_golden",
        headers=_auth_headers(),
        json={"tenant": "acme", "bot": "bot", "csrf_token": csrf},
    )
    assert resp.status_code == 500
    body = resp.json()
    assert body["detail"] == "boom"

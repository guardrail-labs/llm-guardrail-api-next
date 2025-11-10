from __future__ import annotations

from pathlib import Path
from typing import Iterator

import pytest
from starlette.testclient import TestClient

from app.main import create_app
from app.services import config_store


@pytest.fixture()
def admin_client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[TestClient]:
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


def _strict_policy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, content: str = 'policy_version: "strict"\n'
) -> Path:
    strict_path = tmp_path / "strict.yaml"
    strict_path.write_text(content, encoding="utf-8")
    monkeypatch.setenv("STRICT_SECRETS_POLICY_PATH", str(strict_path))
    return strict_path.resolve()


def _demo_policy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, content: str = 'policy_version: "demo"\n'
) -> Path:
    demo_path = tmp_path / "demo.yaml"
    demo_path.write_text(content, encoding="utf-8")
    monkeypatch.setenv("DEMO_POLICY_PATH", str(demo_path))
    return demo_path.resolve()


def test_quick_apply_buttons_render(admin_client: TestClient) -> None:
    resp = admin_client.get("/admin/ui/bindings", headers=_auth_headers())
    assert resp.status_code == 200
    html = resp.text
    assert "Apply Strict Secrets Pack" in html
    assert "Apply Demo Defaults" in html


def test_apply_strict_flow(
    admin_client: TestClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    strict_path = _strict_policy(monkeypatch, tmp_path)

    page = admin_client.get("/admin/ui/bindings?tenant=acme&bot=support", headers=_auth_headers())
    assert page.status_code == 200
    csrf_token = page.cookies.get("ui_csrf")
    assert csrf_token

    response = admin_client.post(
        "/admin/ui/bindings/apply_strict_secrets",
        headers=_auth_headers(),
        json={"tenant": "acme", "bot": "support", "csrf_token": csrf_token},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "success"
    assert payload["message"] == "Applied to acme/support."
    assert payload["binding"]["rules_path"] == str(strict_path)
    assert payload["binding"]["policy_version"]
    bindings_resp = admin_client.get("/admin/bindings", headers=_auth_headers())
    assert bindings_resp.status_code == 200
    doc = bindings_resp.json()
    assert any(
        b["tenant"] == "acme" and b["bot"] == "support" and b.get("rules_path") == str(strict_path)
        for b in doc.get("bindings", [])
    )


def test_apply_demo_flow(
    admin_client: TestClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    demo_path = _demo_policy(monkeypatch, tmp_path)

    page = admin_client.get("/admin/ui/bindings?tenant=tenant&bot=bot", headers=_auth_headers())
    csrf_token = page.cookies.get("ui_csrf")
    assert csrf_token

    response = admin_client.post(
        "/admin/ui/bindings/apply_demo_defaults",
        headers=_auth_headers(),
        json={"tenant": "tenant", "bot": "bot", "csrf_token": csrf_token},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "success"
    assert payload["message"] == "Applied to tenant/bot."
    assert payload["binding"]["rules_path"] == str(demo_path)
    assert payload["binding"]["policy_version"]
    bindings_resp = admin_client.get("/admin/bindings", headers=_auth_headers())
    assert bindings_resp.status_code == 200
    doc = bindings_resp.json()
    assert any(
        b["tenant"] == "tenant" and b["bot"] == "bot" and b.get("rules_path") == str(demo_path)
        for b in doc.get("bindings", [])
    )


def test_reapply_is_idempotent(
    admin_client: TestClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _strict_policy(monkeypatch, tmp_path)

    page = admin_client.get("/admin/ui/bindings?tenant=acme&bot=support", headers=_auth_headers())
    csrf_token = page.cookies.get("ui_csrf")
    assert csrf_token

    first = admin_client.post(
        "/admin/ui/bindings/apply_strict_secrets",
        headers=_auth_headers(),
        json={"tenant": "acme", "bot": "support", "csrf_token": csrf_token},
    )
    assert first.status_code == 200
    assert first.json()["applied"] is True

    second = admin_client.post(
        "/admin/ui/bindings/apply_strict_secrets",
        headers=_auth_headers(),
        json={"tenant": "acme", "bot": "support", "csrf_token": csrf_token},
    )
    assert second.status_code == 200
    payload = second.json()
    assert payload["applied"] is False
    assert payload["status"] == "info"
    assert payload["message"] == "Already applied; refreshed caches."


def test_apply_error_detail_surface(
    admin_client: TestClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    missing_path = tmp_path / "missing.yaml"
    monkeypatch.setenv("STRICT_SECRETS_POLICY_PATH", str(missing_path))

    page = admin_client.get("/admin/ui/bindings?tenant=acme&bot=support", headers=_auth_headers())
    csrf_token = page.cookies.get("ui_csrf")
    assert csrf_token

    response = admin_client.post(
        "/admin/ui/bindings/apply_strict_secrets",
        headers=_auth_headers(),
        json={"tenant": "acme", "bot": "support", "csrf_token": csrf_token},
    )
    assert response.status_code == 404
    body = response.json()
    assert body["detail"] == "Strict secrets policy not found."

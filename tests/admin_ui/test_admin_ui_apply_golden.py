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


def _golden_policy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    content: str = "policy_version: gold\n",
) -> Path:
    golden_path = tmp_path / "golden.yaml"
    golden_path.write_text(content, encoding="utf-8")
    monkeypatch.setenv("GOLDEN_POLICY_PATH", str(golden_path))
    return golden_path.resolve()


def _auth_headers() -> dict[str, str]:
    return {"Authorization": "Bearer secret"}


def test_apply_button_renders(admin_client: TestClient) -> None:
    resp = admin_client.get("/admin/ui/bindings", headers=_auth_headers())
    assert resp.status_code == 200
    assert "Apply Golden Packs" in resp.text


def test_apply_golden_success_flow(
    admin_client: TestClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    golden_path = _golden_policy(monkeypatch, tmp_path)

    initial = admin_client.get("/admin/ui/bindings", headers=_auth_headers())
    assert initial.status_code == 200
    csrf_token = initial.cookies.get("ui_csrf")
    assert csrf_token

    response = admin_client.post(
        "/admin/ui/bindings/apply_golden",
        headers=_auth_headers(),
        json={"tenant": "acme", "bot": "support", "csrf_token": csrf_token},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "success"
    assert payload["message"] == "Golden Packs applied to acme/support."
    assert payload["binding"]["rules_path"] == str(golden_path)

    bindings_doc = config_store.load_bindings()
    assert any(
        b["tenant"] == "acme" and b["bot"] == "support" and b["rules_path"] == str(golden_path)
        for b in bindings_doc.bindings
    )


def test_apply_golden_idempotent_flow(
    admin_client: TestClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _golden_policy(monkeypatch, tmp_path)

    page = admin_client.get("/admin/ui/bindings", headers=_auth_headers())
    csrf = page.cookies.get("ui_csrf")
    assert csrf

    first = admin_client.post(
        "/admin/ui/bindings/apply_golden",
        headers=_auth_headers(),
        json={"tenant": "acme", "bot": "support", "csrf_token": csrf},
    )
    assert first.status_code == 200
    assert first.json()["applied"] is True

    second = admin_client.post(
        "/admin/ui/bindings/apply_golden",
        headers=_auth_headers(),
        json={"tenant": "acme", "bot": "support", "csrf_token": csrf},
    )
    assert second.status_code == 200
    payload = second.json()
    assert payload["applied"] is False
    assert payload["status"] == "info"
    assert payload["message"] == "Already using Golden Packs."


def test_apply_golden_error_surface(
    admin_client: TestClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    missing = tmp_path / "missing.yaml"
    monkeypatch.setenv("GOLDEN_POLICY_PATH", str(missing))

    page = admin_client.get("/admin/ui/bindings", headers=_auth_headers())
    csrf = page.cookies.get("ui_csrf")
    assert csrf

    response = admin_client.post(
        "/admin/ui/bindings/apply_golden",
        headers=_auth_headers(),
        json={"tenant": "acme", "bot": "support", "csrf_token": csrf},
    )
    assert response.status_code == 404
    body = response.json()
    assert body["detail"] == "Golden policy not found."

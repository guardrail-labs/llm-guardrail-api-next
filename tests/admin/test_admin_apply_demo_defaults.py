from __future__ import annotations

from pathlib import Path
from typing import Dict

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import config_store

client = TestClient(app)


@pytest.fixture(autouse=True)
def _reset_bindings(tmp_path, monkeypatch):
    cfg_dir = tmp_path / "config"
    bindings_path = cfg_dir / "bindings.yaml"
    admin_cfg_path = cfg_dir / "admin_config.yaml"
    monkeypatch.setattr(config_store, "_CONFIG_DIR", cfg_dir)
    monkeypatch.setattr(config_store, "_CONFIG_PATH", bindings_path)
    monkeypatch.setattr(config_store, "_ADMIN_CONFIG_PATH", admin_cfg_path)
    config_store.save_bindings([])
    from app import main as main_mod

    main_mod._BINDINGS.clear()
    yield
    main_mod._BINDINGS.clear()


def _make_demo_policy(
    monkeypatch, tmp_path, content: str = 'policy_version: "demo"\n'
) -> Path:
    demo_path = tmp_path / "demo.yaml"
    demo_path.write_text(content, encoding="utf-8")
    monkeypatch.setenv("DEMO_POLICY_PATH", str(demo_path))
    resolved: Path = demo_path.resolve()
    return resolved


def test_apply_demo_defaults_first_time(monkeypatch, tmp_path):
    demo_path = _make_demo_policy(monkeypatch, tmp_path)

    resp = client.post(
        "/admin/bindings/apply_demo_defaults",
        json={"tenant": "acme", "bot": "support"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["applied"] is True
    assert data["rules_path"] == str(demo_path)
    assert data["version"]
    assert data["policy_version"]

    bindings_resp = client.get("/admin/bindings")
    assert bindings_resp.status_code == 200
    doc: Dict[str, object] = bindings_resp.json()
    assert any(
        b["tenant"] == "acme"
        and b["bot"] == "support"
        and b["rules_path"] == str(demo_path)
        for b in doc["bindings"]
    )


def test_apply_demo_defaults_idempotent_refresh(monkeypatch, tmp_path):
    demo_path = _make_demo_policy(monkeypatch, tmp_path, content='policy_version: "1"\n')

    first = client.post(
        "/admin/bindings/apply_demo_defaults",
        json={"tenant": "acme", "bot": "support"},
    )
    assert first.status_code == 200
    assert first.json()["applied"] is True

    demo_path.write_text('policy_version: "2"\n', encoding="utf-8")

    second = client.post(
        "/admin/bindings/apply_demo_defaults",
        json={"tenant": "acme", "bot": "support"},
    )
    assert second.status_code == 200
    data = second.json()
    assert data["applied"] is False
    assert data["rules_path"] == str(demo_path)
    assert data["policy_version"] == "2"

    bindings_resp = client.get("/admin/bindings")
    assert bindings_resp.status_code == 200
    doc = bindings_resp.json()
    assert any(
        b["tenant"] == "acme"
        and b["bot"] == "support"
        and b.get("policy_version") == "2"
        for b in doc["bindings"]
    )


def test_apply_demo_defaults_overwrites_existing(monkeypatch, tmp_path):
    other_path = tmp_path / "other.yaml"
    other_path.write_text("policy_version: other\n", encoding="utf-8")
    config_store.upsert_binding("acme", "support", str(other_path.resolve()))

    demo_path = _make_demo_policy(monkeypatch, tmp_path)

    resp = client.post(
        "/admin/bindings/apply_demo_defaults",
        json={"tenant": "acme", "bot": "support"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["applied"] is True
    assert data["rules_path"] == str(demo_path)

    bindings_resp = client.get("/admin/bindings")
    doc = bindings_resp.json()
    assert any(
        b["tenant"] == "acme"
        and b["bot"] == "support"
        and b["rules_path"] == str(demo_path)
        for b in doc["bindings"]
    )


def test_apply_demo_defaults_missing_params(monkeypatch, tmp_path):
    _make_demo_policy(monkeypatch, tmp_path)

    resp = client.post(
        "/admin/bindings/apply_demo_defaults",
        json={"tenant": "", "bot": "support"},
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["code"] == "bad_request"


def test_apply_demo_defaults_missing_file(monkeypatch):
    monkeypatch.setenv("DEMO_POLICY_PATH", "/tmp/does-not-exist.yaml")

    resp = client.post(
        "/admin/bindings/apply_demo_defaults",
        json={"tenant": "acme", "bot": "support"},
    )
    assert resp.status_code == 404
    body = resp.json()
    assert body["code"] == "not_found"

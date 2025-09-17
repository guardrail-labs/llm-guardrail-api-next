from __future__ import annotations

import types

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.routes import admin_policy_packs as appmod


def _app() -> FastAPI:
    app = FastAPI()
    app.include_router(appmod.router)
    return app


def test_api_packs_uses_list_packs(monkeypatch):
    packs = [
        {
            "id": "pii",
            "version": "1.2.3",
            "path": "/packs/pii.yaml",
            "policy": {"rules": {"redact": [{"id": "email"}]}},
        },
        {
            "id": "secrets",
            "version": "2024-09",
            "source": "repo://policy/secrets.yaml",
            "policy": {"rules": {"redact": [{"id": "key1"}, {"id": "key2"}]}},
        },
    ]
    fake_pol = types.SimpleNamespace(list_packs=lambda: packs)
    monkeypatch.setattr(appmod, "_get_policy_module", lambda: fake_pol)

    app = _app()
    client = TestClient(app)
    response = client.get("/admin/api/policy/packs")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert any(item["id"] == "pii" for item in data["items"])
    assert any(item["rules_redact"] == 2 for item in data["items"])


def test_api_packs_falls_back_to_merged(monkeypatch):
    merged = {
        "packs": [{"id": "baseline", "version": "v1"}],
        "baseline": {"rules": {"redact": [{"id": "r"}], "other": [1, 2]}},
    }
    fake_pol = types.SimpleNamespace(
        get_active_policy=lambda: merged, current_rules_version=lambda: "v-abc"
    )
    monkeypatch.setattr(appmod, "_get_policy_module", lambda: fake_pol)

    app = _app()
    client = TestClient(app)
    response = client.get("/admin/api/policy/packs")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1
    assert data["items"][0]["id"] in ("baseline", "merged")

from __future__ import annotations

import json
import os
import tempfile

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from app.main import create_app
from app.routes.admin_ui import _csrf_token
from app.services import mitigation_store


@pytest.fixture()
def app_factory():
    def _factory():
        mitigation_store.reset_for_tests()
        app = create_app()

        from app.security import rbac as rbac_mod

        def _allow(_: Request) -> None:
            return None

        app.dependency_overrides[rbac_mod.require_viewer] = _allow
        app.dependency_overrides[rbac_mod.require_operator] = _allow
        return app

    return _factory


def test_persist_file_roundtrip(app_factory, monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "mitigation.json")
        monkeypatch.setenv("MITIGATION_STORE_BACKEND", "file")
        monkeypatch.setenv("MITIGATION_STORE_FILE", path)
        monkeypatch.delenv("REDIS_URL", raising=False)

        app = app_factory()
        with TestClient(app) as client:
            token = _csrf_token()
            client.cookies.set("ui_csrf", token)

            response = client.put(
                "/admin/api/mitigation-mode",
                json={"tenant": "t", "bot": "b", "mode": "block", "csrf_token": token},
                headers={"X-CSRF-Token": token},
            )
            assert response.status_code == 200

            with open(path, "r", encoding="utf-8") as handle:
                contents = json.load(handle)
            assert contents.get("t|b") == "block"

            roundtrip = client.get("/admin/api/mitigation-mode", params={"tenant": "t", "bot": "b"})
            assert roundtrip.status_code == 200
            assert roundtrip.json()["mode"] == "block"

            listing = client.get("/admin/api/mitigation-modes")
            assert listing.status_code == 200
            assert any(
                entry["tenant"] == "t" and entry["bot"] == "b" and entry["mode"] == "block"
                for entry in listing.json()
            )


def test_memory_backend_default(app_factory, monkeypatch):
    monkeypatch.delenv("MITIGATION_STORE_BACKEND", raising=False)
    monkeypatch.delenv("MITIGATION_STORE_FILE", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)

    app = app_factory()
    with TestClient(app) as client:
        token = _csrf_token()
        client.cookies.set("ui_csrf", token)

        initial = client.get("/admin/api/mitigation-mode", params={"tenant": "t2", "bot": "b2"})
        assert initial.status_code == 200
        assert initial.json()["mode"] in (None, "block", "clarify", "redact")

        updated = client.put(
            "/admin/api/mitigation-mode",
            json={"tenant": "t2", "bot": "b2", "mode": "clarify", "csrf_token": token},
            headers={"X-CSRF-Token": token},
        )
        assert updated.status_code == 200

        confirm = client.get("/admin/api/mitigation-mode", params={"tenant": "t2", "bot": "b2"})
        assert confirm.status_code == 200
        assert confirm.json()["mode"] == "clarify"

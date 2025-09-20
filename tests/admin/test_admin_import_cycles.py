from __future__ import annotations

import importlib

from fastapi.testclient import TestClient

from app.main import create_app


def test_admin_modules_import_without_cycles() -> None:
    import app.routes.admin_ui as admin_ui

    importlib.reload(admin_ui)

    import app.routes.admin_decisions as admin_decisions

    importlib.reload(admin_decisions)


def test_admin_decisions_page_renders(monkeypatch) -> None:
    monkeypatch.setenv("ADMIN_UI_TOKEN", "secret")

    app = create_app()
    with TestClient(app) as client:
        response = client.get("/admin/ui/decisions", headers={"Authorization": "Bearer secret"})

    assert response.status_code == 200

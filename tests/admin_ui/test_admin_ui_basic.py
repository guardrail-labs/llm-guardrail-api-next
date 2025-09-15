import os

from starlette.testclient import TestClient

from app.main import create_app


def _client() -> TestClient:
    os.environ["ADMIN_UI_TOKEN"] = "secret"
    app = create_app()
    return TestClient(app)


def test_overview_requires_auth() -> None:
    c = TestClient(create_app())
    r = c.get("/admin/ui")
    assert r.status_code == 401


def test_overview_renders_with_bearer() -> None:
    c = _client()
    r = c.get("/admin/ui", headers={"Authorization": "Bearer secret"})
    assert r.status_code == 200
    assert "Policy version" in r.text


def test_reload_with_csrf_ok(monkeypatch) -> None:
    c = _client()
    r = c.get("/admin/ui", headers={"Authorization": "Bearer secret"})
    assert r.status_code == 200
    csrf = r.cookies.get("ui_csrf")
    assert csrf
    r2 = c.post(
        "/admin/ui/reload",
        headers={"Authorization": "Bearer secret"},
        data={"csrf_token": csrf},
    )
    assert r2.status_code == 200
    assert r2.text == "ok"


def test_export_ndjson_auth() -> None:
    c = _client()
    r = c.get(
        "/admin/ui/export/decisions?n=2",
        headers={"Authorization": "Bearer secret"},
    )
    assert r.status_code == 200
    assert r.headers.get("content-type", "").startswith("application/x-ndjson")


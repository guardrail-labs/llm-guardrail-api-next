import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.routes.admin_ui import _csrf_token


@pytest.fixture()
def app_factory():
    def _factory():
        return create_app()

    return _factory


def test_strict_toggle_roundtrip(app_factory, monkeypatch):
    from app.services import policy_store as PS

    calls = {"bound": set(), "unbound": set()}

    def _is_bound(tenant, bot, pack):
        return (tenant, bot, pack) in calls["bound"]

    def _bind_pack(tenant, bot, pack):
        calls["bound"].add((tenant, bot, pack))

    def _unbind_pack(tenant, bot, pack):
        calls["bound"].discard((tenant, bot, pack))
        calls["unbound"].add((tenant, bot, pack))

    monkeypatch.setattr(PS, "is_bound", _is_bound)
    monkeypatch.setattr(PS, "bind_pack", _bind_pack)
    monkeypatch.setattr(PS, "unbind_pack", _unbind_pack)

    app = app_factory()
    client = TestClient(app)
    token = _csrf_token()
    client.cookies.set("ui_csrf", token)

    r0 = client.get("/admin/api/secrets/strict", params={"tenant": "t", "bot": "b"})
    assert r0.status_code == 200
    assert r0.json()["enabled"] is False

    r1 = client.put(
        "/admin/api/secrets/strict",
        json={"tenant": "t", "bot": "b", "enabled": True, "csrf_token": token},
        headers={"X-CSRF-Token": token},
    )
    assert r1.status_code == 200 and r1.json()["ok"] is True
    assert ("t", "b", "secrets_strict") in calls["bound"]

    # Second enable should be idempotent
    r1b = client.put(
        "/admin/api/secrets/strict",
        json={"tenant": "t", "bot": "b", "enabled": True, "csrf_token": token},
        headers={"X-CSRF-Token": token},
    )
    assert r1b.status_code == 200

    r2 = client.get("/admin/api/secrets/strict", params={"tenant": "t", "bot": "b"})
    assert r2.status_code == 200
    assert r2.json()["enabled"] is True

    r3 = client.put(
        "/admin/api/secrets/strict",
        json={"tenant": "t", "bot": "b", "enabled": False, "csrf_token": token},
        headers={"X-CSRF-Token": token},
    )
    assert r3.status_code == 200 and r3.json()["ok"] is True
    assert ("t", "b", "secrets_strict") in calls["unbound"]

    r4 = client.get("/admin/api/secrets/strict", params={"tenant": "t", "bot": "b"})
    assert r4.status_code == 200
    assert r4.json()["enabled"] is False


def test_strict_toggle_requires_csrf(app_factory, monkeypatch):
    from app.services import policy_store as PS

    monkeypatch.setattr(PS, "is_bound", lambda *args, **kwargs: False)
    monkeypatch.setattr(PS, "bind_pack", lambda *args, **kwargs: None)

    app = app_factory()
    client = TestClient(app)

    bad_cookie = "bad-token"
    client.cookies.set("ui_csrf", bad_cookie)
    resp = client.put(
        "/admin/api/secrets/strict",
        json={"tenant": "t", "bot": "b", "enabled": True, "csrf_token": ""},
        headers={"X-CSRF-Token": "mismatch"},
    )
    assert resp.status_code == 400

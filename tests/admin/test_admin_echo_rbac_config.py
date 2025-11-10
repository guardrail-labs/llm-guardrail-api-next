from fastapi import FastAPI
from fastapi.testclient import TestClient


def test_admin_echo_enforces_rbac_when_config_enabled(monkeypatch):
    import app.routes.admin_echo as admin_echo_module
    from app.services import config_store

    # Ensure env flags do NOT indicate RBAC, to force reliance on config
    monkeypatch.delenv("ADMIN_RBAC_ENABLED", raising=False)
    monkeypatch.delenv("RBAC_ENABLED", raising=False)

    # Persisted config enables RBAC; admin guard requires matching key
    monkeypatch.setattr(config_store, "get_config", lambda: {"admin_rbac_enabled": True})
    monkeypatch.setattr(config_store, "is_admin_rbac_enabled", lambda: True)
    monkeypatch.setattr(config_store, "get_admin_api_key", lambda: "secret")

    app = FastAPI()
    app.include_router(admin_echo_module.router)
    client = TestClient(app)

    response = client.get("/admin/echo", params={"text": "hello"})
    assert response.status_code == 403  # RBAC guard was invoked

    response_ok = client.get(
        "/admin/echo", params={"text": "hello"}, headers={"X-Admin-Key": "secret"}
    )
    assert response_ok.status_code == 200


def test_admin_echo_fallbacks_to_key_when_no_guards(monkeypatch):
    import app.routes.admin_echo as admin_echo_module
    from app.services import config_store

    # Ensure env flags do not enable RBAC
    monkeypatch.delenv("ADMIN_RBAC_ENABLED", raising=False)
    monkeypatch.delenv("RBAC_ENABLED", raising=False)

    # Persisted config disables RBAC
    monkeypatch.setattr(config_store, "get_config", lambda: {"admin_rbac_enabled": False})

    # Simulate lack of guards so the dependency falls back to header key
    monkeypatch.setattr(admin_echo_module, "_load_require_admin", lambda request: None)

    app = FastAPI()
    app.include_router(admin_echo_module.router)

    client = TestClient(app)
    # No key configured -> allowed (legacy)
    response = client.get("/admin/echo", params={"text": "hello"})
    assert response.status_code == 200

    # Configure key -> require it
    monkeypatch.setenv("ADMIN_API_KEY", "k")
    response2 = client.get("/admin/echo", params={"text": "hello"})
    assert response2.status_code == 401
    response3 = client.get("/admin/echo", params={"text": "hello"}, headers={"X-Admin-Key": "k"})
    assert response3.status_code == 200

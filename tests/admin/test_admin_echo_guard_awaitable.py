from __future__ import annotations

import asyncio
import functools
import sys
from types import ModuleType

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from pytest import MonkeyPatch


def install_admin_echo(app: FastAPI) -> None:
    from app.routes.admin_echo import router as admin_echo_router

    app.include_router(admin_echo_router)


def _install_guard_modules(monkeypatch: MonkeyPatch, guard) -> None:
    rbac_mod = ModuleType("app.routes.admin_rbac")
    setattr(rbac_mod, "require_admin", guard)
    monkeypatch.setitem(sys.modules, "app.routes.admin_rbac", rbac_mod)

    import app.routes as routes_pkg

    monkeypatch.setattr(routes_pkg, "admin_rbac", rbac_mod, raising=False)

    config_mod = ModuleType("app.services.config_store")

    def get_config() -> dict[str, bool]:
        return {"admin_rbac_enabled": True}

    setattr(config_mod, "get_config", get_config)
    setattr(config_mod, "is_admin_rbac_enabled", lambda: True)
    monkeypatch.setitem(sys.modules, "app.services.config_store", config_mod)

    import app.services as services_pkg

    monkeypatch.setattr(services_pkg, "config_store", config_mod, raising=False)


def test_decorated_async_guard_is_awaited(monkeypatch: MonkeyPatch) -> None:
    # Create an async guard wrapped by a decorator that hides coroutinefunction status.
    called = {"v": False}

    async def base_guard(request):
        await asyncio.sleep(0)
        called["v"] = True
        # deny to prove it ran
        raise HTTPException(status_code=403, detail="nope")

    def deco(fn):
        def wrapper(req):
            # return the coroutine returned by fn(req)
            return fn(req)

        return wrapper

    wrapped = deco(base_guard)

    _install_guard_modules(monkeypatch, wrapped)

    app = FastAPI()
    install_admin_echo(app)
    client = TestClient(app)

    response = client.get("/admin/echo", params={"text": "x"})
    assert response.status_code == 403
    assert called["v"] is True  # proves coroutine was awaited


def test_partial_async_guard_is_awaited(monkeypatch: MonkeyPatch) -> None:
    called = {"v": False}

    async def base_guard(request, flag):
        called["v"] = flag
        raise HTTPException(status_code=403)

    wrapped = functools.partial(base_guard, flag=True)

    _install_guard_modules(monkeypatch, wrapped)

    app = FastAPI()
    install_admin_echo(app)
    client = TestClient(app)

    response = client.get("/admin/echo", params={"text": "y"})
    assert response.status_code == 403
    assert called["v"] is True


def test_callable_class_async_is_awaited(monkeypatch: MonkeyPatch) -> None:
    called = {"v": False}

    class GuardObj:
        async def __call__(self, request):
            called["v"] = True
            raise HTTPException(status_code=403)

    _install_guard_modules(monkeypatch, GuardObj())

    app = FastAPI()
    install_admin_echo(app)
    client = TestClient(app)

    response = client.get("/admin/echo", params={"text": "z"})
    assert response.status_code == 403
    assert called["v"] is True

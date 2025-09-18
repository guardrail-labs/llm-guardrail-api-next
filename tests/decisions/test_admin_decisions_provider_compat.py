from __future__ import annotations

import importlib
import sys
import types
from typing import Callable

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.routes import admin_decisions_api as decisions_api


def _mount_app(monkeypatch) -> FastAPI:
    monkeypatch.setenv("ADMIN_API_KEY", "k")
    monkeypatch.setattr(decisions_api, "_provider", None)
    app = FastAPI()
    app.include_router(decisions_api.router)
    return app


def _stub_module(monkeypatch, provider_factory: Callable[[], types.ModuleType]) -> None:
    module = provider_factory()
    monkeypatch.setitem(sys.modules, "app.services.decisions", module)
    # Ensure auto-detect sees the patched module on reloads
    importlib.invalidate_caches()


def test_provider_new_signature_page_page_size(monkeypatch):
    def list_decisions(
        *,
        page,
        page_size,
        since=None,
        tenant=None,
        bot=None,
        outcome=None,
        sort_key=None,
        sort_dir=None,
    ):
        items = [
            {
                "id": 1,
                "tenant": tenant or "t",
                "bot": bot or "b",
                "outcome": outcome or "allow",
            }
        ]
        total = 1
        return items, total

    def factory() -> types.ModuleType:
        module = types.ModuleType("app.services.decisions")
        module.list_decisions = list_decisions  # type: ignore[attr-defined]
        return module

    _stub_module(monkeypatch, factory)

    app = _mount_app(monkeypatch)
    client = TestClient(app)
    response = client.get(
        "/admin/api/decisions?tenant=T&bot=B",
        headers={"X-Admin-Key": "k"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert payload["items"][0]["tenant"] == "T"
    assert payload["items"][0]["bot"] == "B"


def test_provider_legacy_limit_offset(monkeypatch):
    def list_decisions(
        *,
        limit,
        offset,
        since=None,
        tenant=None,
        bot=None,
        outcome=None,
        sort_key=None,
        sort_dir=None,
    ):
        assert isinstance(limit, int)
        assert isinstance(offset, int)
        return ([{"id": 1}], 1)

    def factory() -> types.ModuleType:
        module = types.ModuleType("app.services.decisions")
        module.list_decisions = list_decisions  # type: ignore[attr-defined]
        return module

    _stub_module(monkeypatch, factory)

    app = _mount_app(monkeypatch)
    client = TestClient(app)
    response = client.get(
        "/admin/api/decisions?page=2&page_size=10",
        headers={"X-Admin-Key": "k"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["page"] == 2
    assert payload["page_size"] == 10
    assert payload["total"] == 1


def test_fallback_to_legacy_query_when_list_decisions_bad(monkeypatch):
    def list_decisions(*_args, **_kwargs):
        raise TypeError("boom")

    def query_decisions(**_kwargs):
        return ([{"id": 1}], 1)

    def factory() -> types.ModuleType:
        module = types.ModuleType("app.services.decisions")
        module.list_decisions = list_decisions  # type: ignore[attr-defined]
        module.query_decisions = query_decisions  # type: ignore[attr-defined]
        return module

    _stub_module(monkeypatch, factory)

    app = _mount_app(monkeypatch)
    client = TestClient(app)
    response = client.get(
        "/admin/api/decisions",
        headers={"X-Admin-Key": "k"},
    )
    assert response.status_code == 200
    assert response.json()["total"] == 1

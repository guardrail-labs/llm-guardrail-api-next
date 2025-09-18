from __future__ import annotations

import importlib
import os
from typing import Callable, Iterable, Tuple

import pytest
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.testclient import TestClient

PolicyDict = dict


def _build_client(
    monkeypatch: pytest.MonkeyPatch,
    merge_fn: Callable[[Iterable[str]], Tuple[PolicyDict, str, list]],
) -> TestClient:
    monkeypatch.setenv("ADMIN_API_KEY", "k")

    from app.routes import admin_policy_api as policy_api, admin_policy_packs, admin_rbac
    from app.services import (
        config_store,
        policy as policy_service,
        policy_packs as policy_packs_service,
        policy_validate_enforce,
    )

    def _require_admin_dep(request: Request) -> None:
        cfg_key = os.environ.get("ADMIN_API_KEY")
        supplied = request.headers.get("X-Admin-Key")
        if cfg_key and supplied != cfg_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Admin authentication required",
            )

    monkeypatch.setattr(admin_policy_packs, "_require_admin_dep", _require_admin_dep)
    monkeypatch.setattr(admin_rbac, "require_admin", lambda _request: None)
    monkeypatch.setattr(
        policy_service,
        "get_active_policy",
        lambda: {"rules": {"redact": [{"id": "x", "pattern": "A"}]}},
    )
    monkeypatch.setattr(policy_service, "current_rules_version", lambda: "v1")
    monkeypatch.setattr(policy_service, "force_reload", lambda: "v2")
    monkeypatch.setattr(policy_service, "get_pack_refs", lambda: [])
    monkeypatch.setattr(policy_packs_service, "merge_packs", merge_fn)
    monkeypatch.setattr(config_store, "get_policy_packs", lambda: ["default"])

    def _validate(_: str):
        return True, {"issues": [], "enforcement_mode": "warn"}

    monkeypatch.setattr(policy_validate_enforce, "validate_text_for_reload", _validate)

    importlib.reload(policy_api)

    app = FastAPI()
    app.include_router(policy_api.router)
    return TestClient(app)


def test_get_diff_requires_admin_and_returns_json(monkeypatch: pytest.MonkeyPatch) -> None:
    def merge(names: Iterable[str]):
        assert list(names) == ["foo", "bar"]
        return (
            {"rules": {"redact": [{"id": "x", "pattern": "B"}, {"id": "y", "pattern": "C"}]}},
            "hash",
            [],
        )

    client = _build_client(monkeypatch, merge)

    resp = client.get("/admin/api/policy/diff?packs=foo,bar")
    assert resp.status_code == 401

    resp = client.get("/admin/api/policy/diff?packs=foo,bar", headers={"X-Admin-Key": "k"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["packs"] == ["foo", "bar"]
    assert data["diff"]["summary"]["changed"] == 1
    assert data["diff"]["summary"]["added"] == 1


def test_get_diff_handles_missing_pack(monkeypatch: pytest.MonkeyPatch) -> None:
    def merge(_: Iterable[str]):
        raise FileNotFoundError("missing pack")

    client = _build_client(monkeypatch, merge)

    resp = client.get("/admin/api/policy/diff?packs=missing", headers={"X-Admin-Key": "k"})
    assert resp.status_code == 404
    assert resp.json()["detail"] == "missing pack"

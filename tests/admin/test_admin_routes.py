from __future__ import annotations

import os
from typing import List

from fastapi.testclient import TestClient

from app.main import app  # existing FastAPI app
from app.services.bindings.models import Binding
from app.services.bindings.repository import get_bindings


client = TestClient(app)


def test_admin_index_ok() -> None:
    r = client.get("/admin")
    assert r.status_code == 200
    assert "Guardrail Admin" in r.text


def test_bindings_apply_dry_run(monkeypatch) -> None:
    monkeypatch.setenv("ADMIN_ENABLE_APPLY", "0")
    payload = {
        "bindings": [
            {
                "tenant_id": "*",
                "bot_id": "b1",
                "policy_version": "p1",
                "priority": 1,
            },
            {
                "tenant_id": "t1",
                "bot_id": "b1",
                "policy_version": "p2",
                "priority": 5,
            },
        ]
    }
    r = client.post("/admin/bindings/apply", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["applied"] is False
    assert data["apply_enabled"] is False
    assert len(get_bindings()) == 0  # nothing persisted


def test_bindings_apply_enabled(monkeypatch) -> None:
    monkeypatch.setenv("ADMIN_ENABLE_APPLY", "1")
    payload = {
        "bindings": [
            {
                "tenant_id": "*",
                "bot_id": "b1",
                "policy_version": "p1",
                "priority": 1,
            },
            {
                "tenant_id": "t1",
                "bot_id": "b1",
                "policy_version": "p2",
                "priority": 5,
            },
        ]
    }
    r = client.post("/admin/bindings/apply", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["applied"] is True
    assert data["apply_enabled"] is True

    # Page renders with table
    r2 = client.get("/admin/bindings")
    assert r2.status_code == 200
    assert "p1" in r2.text or "p2" in r2.text


def test_active_policy_view(monkeypatch) -> None:
    monkeypatch.setenv("ADMIN_ENABLE_APPLY", "1")
    # Ensure we have at least one binding
    payload = {
        "bindings": [
            {
                "tenant_id": "*",
                "bot_id": "b1",
                "policy_version": "p1",
                "priority": 1,
            },
            {
                "tenant_id": "t1",
                "bot_id": "b1",
                "policy_version": "p2",
                "priority": 5,
            },
        ]
    }
    client.post("/admin/bindings/apply", json=payload)

    r = client.get("/admin/active-policy", params={"tenant": "t1", "bot": "b1"})
    assert r.status_code == 200
    assert "Selected" in r.text


def test_admin_metrics_redirect() -> None:
    r = client.get("/admin/metrics", allow_redirects=False)
    assert r.status_code in (302, 307)
    assert r.headers.get("location") == "/metrics"

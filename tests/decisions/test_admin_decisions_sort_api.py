from __future__ import annotations

import sys
import types

from fastapi import FastAPI
from fastapi.testclient import TestClient


def make_app() -> FastAPI:
    app = FastAPI()

    rows = [
        {
            "id": 1,
            "ts": "2025-09-18T10:00:00Z",
            "tenant": "b",
            "bot": "z",
            "outcome": "allow",
            "policy_version": "1",
            "rule_id": "r1",
            "incident_id": "i1",
        },
        {
            "id": 2,
            "ts": "2025-09-18T09:00:00Z",
            "tenant": "a",
            "bot": "y",
            "outcome": "block_input_only",
            "policy_version": "1",
            "rule_id": "r2",
            "incident_id": "i2",
        },
        {
            "id": 3,
            "ts": "2025-09-18T11:00:00Z",
            "tenant": "a",
            "bot": "x",
            "outcome": "redact",
            "policy_version": "2",
            "rule_id": "r3",
            "incident_id": "i3",
        },
    ]

    def list_decisions(**kwargs):
        sort_key = kwargs.get("sort_key", "ts")
        sort_dir = kwargs.get("sort_dir", "desc")
        reverse = sort_dir == "desc"

        def key(row):
            return (row.get(sort_key), row.get("id", 0))

        items = sorted(rows, key=key, reverse=reverse)
        return items, len(items)

    module = types.ModuleType("app.services.decisions")
    module.list_decisions = list_decisions  # type: ignore[attr-defined]
    sys.modules["app.services.decisions"] = module

    from app.routes import admin_decisions_api
    from app.routes.admin_decisions_api import router as router

    def provider(
        since,
        tenant,
        bot,
        outcome,
        limit,
        offset,
        sort_key="ts",
        sort_dir="desc",
    ):
        items, total = list_decisions(sort_key=sort_key, sort_dir=sort_dir)
        start = offset
        end = offset + limit
        return items[start:end], total

    previous_provider = getattr(admin_decisions_api, "_provider", None)
    admin_decisions_api.set_decision_provider(provider)

    def restore_provider() -> None:
        admin_decisions_api._provider = previous_provider

    app.add_event_handler("shutdown", restore_provider)
    app.include_router(router)
    return app


def test_sort_by_tenant_asc() -> None:
    with TestClient(make_app()) as client:
        response = client.get(
            "/admin/api/decisions?sort=tenant&dir=asc",
            headers={"X-Admin-Key": "k"},
        )
        assert response.status_code == 200
        tenants = [row["tenant"] for row in response.json()["items"]]
        assert tenants == ["a", "a", "b"]


def test_sort_default_ts_desc() -> None:
    with TestClient(make_app()) as client:
        response = client.get(
            "/admin/api/decisions",
            headers={"X-Admin-Key": "k"},
        )
        assert response.status_code == 200
        timestamps = [row["ts"] for row in response.json()["items"]]
        assert timestamps == [
            "2025-09-18T11:00:00Z",
            "2025-09-18T10:00:00Z",
            "2025-09-18T09:00:00Z",
        ]


def test_invalid_sort_falls_back() -> None:
    with TestClient(make_app()) as client:
        response = client.get(
            "/admin/api/decisions?sort=__bad__&dir=wat",
            headers={"X-Admin-Key": "k"},
        )
        assert response.status_code == 200
        timestamps = [row["ts"] for row in response.json()["items"]]
        assert timestamps[0] == "2025-09-18T11:00:00Z"

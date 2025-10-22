from __future__ import annotations

import asyncio
from typing import Dict, List, Tuple

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.routes.admin_rbac import require_admin
from app.routes.admin_ui import require_auth
from app.routes.admin_webhooks import _require_csrf_dep
from app.runtime import get_purge_coordinator, get_retention_store
from app.services.purge_coordinator import PurgeCoordinator
from app.services.purge_receipts import HmacSigner
from app.services.purge_targets import PurgeTarget
from app.services.retention import InMemoryRetentionStore, Resource, RetentionPolicy


class DummyTarget(PurgeTarget):
    def __init__(self) -> None:
        self.expired: Dict[Tuple[str, str], List[str]] = {}
        self.purged: List[List[str]] = []

    async def list_expired(self, tenant: str, now: float, limit: int) -> List[str]:
        key = (tenant, Resource.DLQ_MSG.value)
        items = list(self.expired.get(key, []))
        return items[:limit]

    async def purge_ids(self, tenant: str, ids: List[str]) -> int:
        self.purged.append(list(ids))
        return len(ids)


@pytest.fixture()
def client() -> TestClient:
    fakeredis = pytest.importorskip("fakeredis.aioredis")
    redis = fakeredis.FakeRedis(decode_responses=False)
    store = InMemoryRetentionStore()
    target = DummyTarget()
    signer = HmacSigner(b"secret", "kid-api")
    coordinator = PurgeCoordinator(
        redis,
        store,
        signer,
        {Resource.DLQ_MSG.value: target},
    )

    app = create_app()

    app.dependency_overrides[require_auth] = lambda: None
    app.dependency_overrides[require_admin] = lambda: None
    app.dependency_overrides[_require_csrf_dep] = lambda: None
    app.dependency_overrides[get_retention_store] = lambda: store
    app.dependency_overrides[get_purge_coordinator] = lambda: coordinator

    async def seed_policy() -> None:
        policy = RetentionPolicy(
            tenant="acme",
            resource=Resource.DLQ_MSG,
            ttl_seconds=60,
            enabled=True,
        )
        await store.set_policy(policy)

    asyncio.run(seed_policy())
    target.expired[("acme", Resource.DLQ_MSG.value)] = ["msg1", "msg2", "msg3"]
    client = TestClient(app)
    return client


def test_policy_upsert_and_list(client: TestClient) -> None:
    resp = client.put(
        "/admin/retention/policies",
        json={
            "tenant": "acme",
            "resource": Resource.DLQ_MSG.value,
            "ttl_seconds": 120,
            "enabled": True,
        },
    )
    assert resp.status_code == 200
    listed = client.get("/admin/retention/policies", params={"tenant": "acme"})
    assert listed.status_code == 200
    policies = listed.json()["policies"]
    assert any(p["resource"] == Resource.DLQ_MSG.value for p in policies)


def test_plan_and_purge_flow(client: TestClient) -> None:
    plan = client.post(
        "/admin/retention/plan",
        json={
            "tenant": "acme",
            "resource": Resource.DLQ_MSG.value,
            "limit": 2,
        },
    )
    assert plan.status_code == 200
    data = plan.json()
    assert data["count"] == 2

    purge = client.post(
        "/admin/retention/purge",
        json={
            "tenant": "acme",
            "resource": Resource.DLQ_MSG.value,
            "limit": 2,
            "dry_run": True,
            "actor": "api",
        },
    )
    assert purge.status_code == 200
    body = purge.json()
    assert body["receipt"]["dry_run"] is True
    receipt_id = body["receipt"]["id"]
    assert body["signature"]["kid"] == "kid-api"

    detail = client.get(f"/admin/retention/receipts/{receipt_id}")
    assert detail.status_code == 200
    verify = client.post(f"/admin/retention/verify/{receipt_id}")
    assert verify.status_code == 200
    assert verify.json()["valid"] is True

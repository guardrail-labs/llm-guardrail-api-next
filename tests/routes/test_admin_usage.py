from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from starlette.testclient import TestClient

pytest.importorskip("sqlalchemy")
pytest.importorskip("aiosqlite")

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.base import Base
from app.main import create_app
from app.models.decision import Decision
from app.routes import admin_usage


@pytest.fixture()
async def db_session() -> AsyncSession:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        yield session
        await session.rollback()

    await engine.dispose()


@pytest.fixture()
def client_with_db(db_session: AsyncSession) -> TestClient:
    app = create_app()

    async def _override_db_session() -> AsyncSession:
        yield db_session

    app.dependency_overrides[admin_usage.get_db_session] = _override_db_session

    with TestClient(app) as client:
        yield client


@pytest.mark.asyncio
async def test_get_usage_by_tenant_basic(
    client_with_db: TestClient,
    db_session: AsyncSession,
) -> None:
    now = datetime.now(timezone.utc)
    earlier = now - timedelta(days=1)

    db_session.add_all(
        [
            Decision(
                id="d1",
                tenant="tenant-a",
                bot="prod",
                outcome="allow",
                ts=now,
            ),
            Decision(
                id="d2",
                tenant="tenant-a",
                bot="prod",
                outcome="block",
                ts=now,
            ),
            Decision(
                id="d3",
                tenant="tenant-b",
                bot="staging",
                outcome="clarify",
                ts=earlier,
            ),
        ]
    )
    await db_session.commit()

    resp = client_with_db.get(
        "/admin/api/usage/by-tenant",
        params={"period": "2d"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    tenants = {row["tenant_id"] for row in data}
    assert "tenant-a" in tenants

    row_a = next(r for r in data if r["tenant_id"] == "tenant-a")
    assert row_a["environment"] == "prod"
    assert row_a["total"] == row_a["allow"] + row_a["block"] + row_a["clarify"]


@pytest.mark.asyncio
async def test_get_usage_by_tenant_requires_admin(
    monkeypatch: pytest.MonkeyPatch,
    db_session: AsyncSession,
) -> None:
    monkeypatch.setenv("ADMIN_UI_AUTH", "1")
    monkeypatch.setenv("ADMIN_UI_TOKEN", "secret")

    app = create_app()

    async def _override_db_session() -> AsyncSession:
        yield db_session

    app.dependency_overrides[admin_usage.get_db_session] = _override_db_session

    with TestClient(app) as client:
        resp = client.get("/admin/api/usage/by-tenant")

    assert resp.status_code in (401, 403)

from __future__ import annotations

import types
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from starlette.testclient import TestClient

pytest.importorskip("sqlalchemy")
pytest.importorskip("aiosqlite")

from sqlalchemy import DateTime, Integer, String, case, func
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.dependencies.auth import AdminAuthDependency
from app.dependencies.db import get_db_session
from app.main import create_app
from app.routes import admin_usage
from app.services import decisions_store


class Base(DeclarativeBase):
    pass


class Decision(Base):
    __tablename__ = "decisions"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String, nullable=False)
    environment: Mapped[str] = mapped_column(String, nullable=False)
    outcome: Mapped[str] = mapped_column(String, nullable=False)
    total_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


@pytest.fixture()
async def db_session(monkeypatch: pytest.MonkeyPatch) -> AsyncSession:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        monkeypatch.setattr(
            decisions_store,
            "decisions_service",
            types.SimpleNamespace(Decision=Decision, func=func, case=case),
            raising=False,
        )
        yield session
        await session.rollback()

    await engine.dispose()


@pytest.fixture()
def client_with_db(db_session: AsyncSession) -> TestClient:
    app = create_app()

    async def _override_db_session() -> AsyncSession:
        yield db_session

    # Bypass admin RBAC so usage endpoints hit the DB-backed logic in tests
    def _allow_admin() -> None:
        return None

    app.dependency_overrides[get_db_session] = _override_db_session
    app.dependency_overrides[AdminAuthDependency] = _allow_admin

    with TestClient(app) as client:
        yield client


@pytest.fixture()
async def seeded_decisions(db_session: AsyncSession) -> None:
    _seed_decisions(db_session)
    await db_session.commit()


def _seed_decisions(session: AsyncSession) -> None:
    now = datetime.now(timezone.utc)
    earlier = now - timedelta(days=2)
    middle = now - timedelta(days=1)

    session.add_all(
        [
            Decision(
                id="d1",
                tenant_id="acme",
                environment="prod",
                outcome="allow",
                total_tokens=100,
                created_at=earlier,
            ),
            Decision(
                id="d2",
                tenant_id="acme",
                environment="prod",
                outcome="block",
                total_tokens=50,
                created_at=middle,
            ),
            Decision(
                id="d3",
                tenant_id="acme",
                environment="dev",
                outcome="clarify",
                total_tokens=25,
                created_at=now,
            ),
            Decision(
                id="d4",
                tenant_id="beta",
                environment="prod",
                outcome="allow",
                total_tokens=10,
                created_at=middle,
            ),
        ]
    )


@pytest.mark.asyncio
async def test_get_usage_by_tenant_happy_path(
    client_with_db: TestClient,
    db_session: AsyncSession,
) -> None:
    _seed_decisions(db_session)
    await db_session.commit()

    resp = client_with_db.get("/admin/api/usage/by-tenant")
    assert resp.status_code == 200
    data = resp.json()

    assert isinstance(data, list)
    expected_keys = {
        "tenant_id",
        "environment",
        "total",
        "allow",
        "block",
        "clarify",
        "total_tokens",
        "first_seen_at",
        "last_seen_at",
    }
    for row in data:
        assert expected_keys.issubset(row.keys())
        assert row["total"] == row["allow"] + row["block"] + row["clarify"]

    keyed = {(r["tenant_id"], r["environment"]): r for r in data}

    acme_prod = keyed[("acme", "prod")]
    assert acme_prod["total"] == 2
    assert acme_prod["allow"] == 1
    assert acme_prod["block"] == 1
    assert acme_prod["clarify"] == 0
    assert acme_prod["total_tokens"] == 150
    assert acme_prod["first_seen_at"] < acme_prod["last_seen_at"]

    acme_dev = keyed[("acme", "dev")]
    assert acme_dev["clarify"] == 1
    assert acme_dev["total_tokens"] == 25
    assert acme_dev["first_seen_at"] == acme_dev["last_seen_at"]

    beta_prod = keyed[("beta", "prod")]
    assert beta_prod["allow"] == 1
    assert beta_prod["total_tokens"] == 10


@pytest.mark.asyncio
async def test_get_usage_by_tenant_filtered(client_with_db: TestClient, db_session: AsyncSession) -> None:
    _seed_decisions(db_session)
    await db_session.commit()

    resp = client_with_db.get("/admin/api/usage/by-tenant", params={"tenant_id": "acme"})
    assert resp.status_code == 200
    data = resp.json()
    assert {(r["tenant_id"], r["environment"]) for r in data} == {
        ("acme", "prod"),
        ("acme", "dev"),
    }


@pytest.mark.asyncio
async def test_get_usage_summary(client_with_db: TestClient, db_session: AsyncSession) -> None:
    _seed_decisions(db_session)
    await db_session.commit()

    resp = client_with_db.get("/admin/api/usage/summary", params={"period": "30d"})
    assert resp.status_code == 200
    data = resp.json()

    expected_keys = {
        "period",
        "tenant",
        "total",
        "allow",
        "block",
        "clarify",
        "total_tokens",
        "tenant_count",
        "environment_count",
        "first_seen_at",
        "last_seen_at",
    }
    assert set(data.keys()) == expected_keys
    assert data["period"] == "30d"
    assert data["tenant"] is None
    assert data["total"] == data["allow"] + data["block"] + data["clarify"]

    assert data["total"] == 4
    assert data["allow"] == 2
    assert data["block"] == 1
    assert data["clarify"] == 1
    assert data["total_tokens"] == 185
    assert data["tenant_count"] == 2
    assert data["environment_count"] == 2

    first_seen = datetime.fromisoformat(data["first_seen_at"])
    last_seen = datetime.fromisoformat(data["last_seen_at"])
    assert first_seen < last_seen


def test_admin_usage_summary_basic(
    client_with_db: TestClient, seeded_decisions: None
) -> None:
    resp = client_with_db.get("/admin/api/usage/summary?period=30d")
    assert resp.status_code == 200
    data = resp.json()

    assert data["period"] == "30d"
    assert "total" in data
    assert "allow" in data
    assert "block" in data
    assert "clarify" in data
    assert "total_tokens" in data
    assert "tenant_count" in data
    assert "environment_count" in data
    # Sanity check: total == allow + block + clarify
    assert data["total"] == data["allow"] + data["block"] + data["clarify"]


@pytest.mark.asyncio
async def test_get_usage_summary_filtered(
    client_with_db: TestClient, db_session: AsyncSession
) -> None:
    _seed_decisions(db_session)
    await db_session.commit()

    resp = client_with_db.get(
        "/admin/api/usage/summary", params={"period": "30d", "tenant_id": "acme"}
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["tenant"] == "acme"
    assert data["total"] == 3
    assert data["allow"] == 1
    assert data["block"] == 1
    assert data["clarify"] == 1
    assert data["total_tokens"] == 175
    assert data["tenant_count"] == 1
    assert data["environment_count"] == 2


@pytest.mark.asyncio
async def test_export_usage_csv(client_with_db: TestClient, db_session: AsyncSession) -> None:
    _seed_decisions(db_session)
    await db_session.commit()

    json_resp = client_with_db.get("/admin/api/usage/by-tenant")
    assert json_resp.status_code == 200
    json_data = json_resp.json()
    keyed = {(r["tenant_id"], r["environment"]): r for r in json_data}

    resp = client_with_db.get("/admin/api/usage/export")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")

    csv_lines = resp.text.splitlines()
    assert csv_lines
    header = csv_lines[0].split(",")
    assert header == [
        "tenant_id",
        "environment",
        "total",
        "allow",
        "block",
        "clarify",
        "total_tokens",
        "first_seen_at",
        "last_seen_at",
    ]

    assert len(csv_lines) > 1
    first_data = csv_lines[1].split(",")
    key = (first_data[0], first_data[1])
    assert key in keyed
    expected = keyed[key]
    assert first_data[2] == str(expected["total"])
    assert first_data[3] == str(expected["allow"])
    assert first_data[4] == str(expected["block"])
    assert first_data[5] == str(expected["clarify"])
    assert first_data[6] == str(expected["total_tokens"])


@pytest.mark.asyncio
async def test_usage_endpoints_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    app = create_app()

    async def _unavailable_db() -> None:
        raise HTTPException(
            status_code=503,
            detail="Database session dependency unavailable for usage metrics",
        )

    app.dependency_overrides[admin_usage.get_db_session] = _unavailable_db

    with TestClient(app) as client:
        resp1 = client.get("/admin/api/usage/by-tenant")
        resp2 = client.get("/admin/api/usage/export")
        resp3 = client.get("/admin/api/usage/summary")

    for resp in (resp1, resp2, resp3):
        assert resp.status_code == 503
        assert "usage metrics" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_get_usage_by_tenant_requires_admin(
    monkeypatch: pytest.MonkeyPatch, db_session: AsyncSession
) -> None:
    monkeypatch.setenv("ADMIN_UI_AUTH", "1")
    monkeypatch.setenv("ADMIN_UI_TOKEN", "secret")

    app = create_app()

    async def _override_db_session() -> AsyncSession:
        yield db_session

    app.dependency_overrides[admin_usage.get_db_session] = _override_db_session

    with TestClient(app) as client:
        resp1 = client.get("/admin/api/usage/by-tenant")
        resp2 = client.get("/admin/api/usage/export")
        resp3 = client.get("/admin/api/usage/summary")

    assert resp1.status_code in (401, 403)
    assert resp2.status_code in (401, 403)
    assert resp3.status_code in (401, 403)

from __future__ import annotations

import types
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("aiosqlite")

from sqlalchemy import DateTime, String
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.schemas.usage import UsageRow, UsageSummary  # noqa: E402
from app.services import decisions_store  # noqa: E402
from app.services.decisions_store import aggregate_usage_by_tenant, summarize_usage  # noqa: E402


class Base(DeclarativeBase):
    pass


class Decision(Base):
    __tablename__ = "decisions"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String, nullable=False)
    environment: Mapped[str] = mapped_column(String, nullable=False)
    decision: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


@pytest.fixture()
async def db_session(monkeypatch: pytest.MonkeyPatch) -> AsyncSession:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        if decisions_store.decisions_service is not None:
            # Patch the Decision model used by aggregate_usage_by_tenant
            monkeypatch.setattr(
                decisions_store.decisions_service,
                "Decision",
                Decision,
                raising=False,
            )
        else:
            # Fallback for environments where decisions_service is absent
            monkeypatch.setattr(decisions_store, "Decision", Decision, raising=False)
        yield session
        await session.rollback()

    await engine.dispose()


@pytest.mark.asyncio
async def test_aggregate_usage_by_tenant_basic(db_session: AsyncSession) -> None:
    now = datetime.now(timezone.utc)
    earlier = now - timedelta(days=1)

    db_session.add_all(
        [
            Decision(
                id="d1",
                tenant_id="t1",
                environment="prod",
                decision="allow",
                created_at=now,
            ),
            Decision(
                id="d2",
                tenant_id="t1",
                environment="prod",
                decision="block",
                created_at=now,
            ),
            Decision(
                id="d3",
                tenant_id="t2",
                environment="staging",
                decision="clarify",
                created_at=now,
            ),
        ]
    )
    await db_session.commit()

    rows = await aggregate_usage_by_tenant(
        db_session,
        start=earlier,
        end=now + timedelta(seconds=1),
        tenant_ids=None,
    )

    assert rows
    keyed = {(r.tenant_id, r.environment): r for r in rows}
    assert keyed[("t1", "prod")].total == 2
    assert keyed[("t1", "prod")].allow == 1
    assert keyed[("t1", "prod")].block == 1
    assert keyed[("t1", "prod")].clarify == 0
    assert keyed[("t1", "prod")].total_tokens == 0
    assert keyed[("t2", "staging")].total == 1
    assert keyed[("t2", "staging")].allow == 0
    assert keyed[("t2", "staging")].block == 0
    assert keyed[("t2", "staging")].clarify == 1
    assert keyed[("t2", "staging")].total_tokens == 0


@pytest.mark.asyncio
async def test_aggregate_usage_by_tenant_filter(db_session: AsyncSession) -> None:
    now = datetime.now(timezone.utc)
    earlier = now - timedelta(days=2)

    db_session.add_all(
        [
            Decision(
                id="d1",
                tenant_id="t1",
                environment="prod",
                decision="allow",
                created_at=now,
            ),
            Decision(
                id="d2",
                tenant_id="t2",
                environment="prod",
                decision="block",
                created_at=now,
            ),
        ]
    )
    await db_session.commit()

    rows = await aggregate_usage_by_tenant(
        db_session,
        start=earlier,
        end=now + timedelta(seconds=1),
        tenant_ids=["t1"],
    )

    assert len(rows) == 1
    assert rows[0].tenant_id == "t1"


@pytest.mark.asyncio
async def test_aggregate_usage_with_legacy_decision_column(
    monkeypatch: pytest.MonkeyPatch, db_session: AsyncSession
) -> None:
    class LegacyDecision(Decision):
        __tablename__ = "legacy_decisions"

    # Swap in the legacy model that exposes a ``decision`` column instead of outcome.
    monkeypatch.setattr(decisions_store, "decisions_service", types.SimpleNamespace(Decision=LegacyDecision))
    await db_session.run_sync(LegacyDecision.__table__.create)

    db_session.add_all(
        [
            LegacyDecision(
                id="l1",
                tenant_id="legacy",
                environment="prod",
                decision="allow",
                created_at=datetime.now(timezone.utc),
            ),
            LegacyDecision(
                id="l2",
                tenant_id="legacy",
                environment="prod",
                decision="block",
                created_at=datetime.now(timezone.utc),
            ),
            LegacyDecision(
                id="l3",
                tenant_id="legacy",
                environment="prod",
                decision="clarify",
                created_at=datetime.now(timezone.utc),
            ),
        ]
    )
    await db_session.commit()

    rows = await aggregate_usage_by_tenant(db_session)
    keyed = {(r.tenant_id, r.environment): r for r in rows}
    legacy = keyed[("legacy", "prod")]

    assert legacy.allow == 1
    assert legacy.block == 1
    assert legacy.clarify == 1
    assert legacy.total == 3


def test_summarize_usage_rollup() -> None:
    rows = [
        UsageRow(tenant_id="t1", environment="prod", decision="allow", count=2),
        UsageRow(tenant_id="t1", environment="prod", decision="block", count=1),
        UsageRow(tenant_id="t1", environment="prod", decision="clarify", count=3),
    ]

    summaries = summarize_usage(rows)
    assert len(summaries) == 1
    s = summaries[0]
    assert s.tenant_id == "t1"
    assert s.environment == "prod"
    assert s.total == 6
    assert s.allow == 2
    assert s.block == 1
    assert s.clarify == 3

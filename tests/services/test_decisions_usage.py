from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("aiosqlite")

from sqlalchemy import DateTime, String
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.schemas.usage import UsageRow, UsageSummary  # noqa: E402
from app.services import decisions_store  # noqa: E402
from app.services.decisions_store import (  # noqa: E402
    aggregate_usage_by_tenant,
    summarize_usage,
)


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
        monkeypatch.setattr(decisions_store, "Decision", Decision)
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
    keys = {(r.tenant_id, r.environment, r.decision) for r in rows}
    assert ("t1", "prod", "allow") in keys
    assert ("t1", "prod", "block") in keys
    assert ("t2", "staging", "clarify") in keys


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

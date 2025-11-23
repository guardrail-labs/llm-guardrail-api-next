from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import AsyncIterator, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

try:  # pragma: no cover - optional dependency
    from sqlalchemy.ext.asyncio import (
        AsyncEngine,
        AsyncSession,
        async_sessionmaker,
        create_async_engine,
    )
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    AsyncEngine = AsyncSession = async_sessionmaker = create_async_engine = None  # type: ignore[assignment]
    _SQLALCHEMY_MISSING = True
else:
    _SQLALCHEMY_MISSING = False

from app.routes.admin_rbac import require_admin as require_admin_rbac
from app.security.admin_auth import require_admin
from app.schemas.usage import UsageSummary
from app.services.decisions_store import (
    aggregate_usage_by_tenant,
    summarize_usage,
)

router = APIRouter(tags=["admin-usage"])

_async_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def _resolve_async_dsn() -> str:
    dsn = os.getenv("DECISIONS_DSN", "sqlite:///./data/decisions.db")
    if dsn.startswith("sqlite+aiosqlite://") or dsn.startswith("postgresql+asyncpg://"):
        return dsn
    if dsn.startswith("sqlite://"):
        return dsn.replace("sqlite://", "sqlite+aiosqlite://", 1)
    if dsn.startswith("postgresql://"):
        return dsn.replace("postgresql://", "postgresql+asyncpg://", 1)
    return dsn


def _get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    if _SQLALCHEMY_MISSING or async_sessionmaker is None or create_async_engine is None:
        raise HTTPException(status_code=503, detail="SQLAlchemy async dependencies not installed")

    global _async_engine, _sessionmaker
    if _sessionmaker is None:
        _async_engine = create_async_engine(_resolve_async_dsn(), future=True)
        _sessionmaker = async_sessionmaker(_async_engine, expire_on_commit=False)
    return _sessionmaker


async def get_db_session() -> AsyncIterator[AsyncSession]:
    sessionmaker = _get_sessionmaker()
    async with sessionmaker() as session:
        yield session


def _resolve_period(period: str) -> tuple[datetime, datetime]:
    """Resolve period strings like '7d', '30d', 'current_month' into [start, end)."""
    now = datetime.now(timezone.utc)

    if period == "current_month":
        start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        next_month = (start + timedelta(days=32)).replace(day=1)
        return start, next_month

    if period.endswith("d") and period[:-1].isdigit():
        days = int(period[:-1])
        end = now
        start = end - timedelta(days=days)
        return start, end

    # fallback: 30 days
    end = now
    start = end - timedelta(days=30)
    return start, end


@router.get(
    "/admin/api/usage/by-tenant",
    response_model=List[UsageSummary],
    summary="Aggregate decision usage by tenant and environment",
)
async def get_usage_by_tenant(
    period: str = Query(
        "30d",
        description="Time window, e.g. '7d', '30d', 'current_month'",
    ),
    tenant_ids: Optional[List[str]] = Query(
        default=None,
        alias="tenant_id",
        description="Optional list of tenant IDs to filter on",
    ),
    session: AsyncSession = Depends(get_db_session),
    _admin_ui = Depends(require_admin),
    _admin_rbac = Depends(require_admin_rbac),
) -> List[UsageSummary]:
    start, end = _resolve_period(period)

    rows = await aggregate_usage_by_tenant(
        session,
        start=start,
        end=end,
        tenant_ids=tenant_ids,
    )

    return summarize_usage(rows)

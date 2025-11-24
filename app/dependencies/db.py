from __future__ import annotations

from typing import TYPE_CHECKING, AsyncGenerator

from fastapi import HTTPException

try:  # pragma: no cover - optional dependency resolution
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.db.session import get_session  # type: ignore[attr-defined]
except ModuleNotFoundError:  # pragma: no cover - DB not configured
    AsyncSession = None  # type: ignore[assignment]
    get_session = None  # type: ignore[assignment]

if TYPE_CHECKING:  # pragma: no cover
    pass


async def get_db_session() -> AsyncGenerator["AsyncSession", None]:
    """
    Shared DB session dependency for admin / usage endpoints.

    Returns 503 when DB or SQLAlchemy is not available so that:
    - Routes still import and register.
    - Enterprise console can show a friendly "usage not configured" state.
    """

    if AsyncSession is None or get_session is None:
        raise HTTPException(
            status_code=503,
            detail="Database session dependency unavailable for usage metrics",
        )

    async with get_session() as session:
        yield session  # type: ignore[misc]

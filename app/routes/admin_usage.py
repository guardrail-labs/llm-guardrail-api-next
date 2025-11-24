from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.dependencies.auth import AdminAuthDependency
from app.dependencies.db import get_db_session
from app.schemas.usage import AdminUsagePeriodSummary
from app.services import decisions_store

router = APIRouter(
    prefix="/admin/api/usage",
    tags=["admin-usage"],
    dependencies=[Depends(AdminAuthDependency)],
)


class TenantUsageSummary(BaseModel):
    tenant_id: str
    environment: str
    total: int = Field(..., ge=0)
    allow: int = Field(..., ge=0)
    block: int = Field(..., ge=0)
    clarify: int = Field(..., ge=0)
    total_tokens: int = Field(..., ge=0)
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None


def _parse_iso8601_or_none(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid datetime format: {value!r}. Use ISO 8601.",
        )


def _resolve_period(period: str) -> Tuple[datetime, datetime]:
    now = datetime.now(timezone.utc)
    key = (period or "").strip().lower()

    if key.endswith("d") and key[:-1].isdigit():
        days = int(key[:-1])
        return now - timedelta(days=days), now

    if key == "current_month":
        start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        if start.month == 12:
            end = start.replace(year=start.year + 1, month=1, day=1)
        else:
            end = start.replace(month=start.month + 1, day=1)
        return start, end

    raise HTTPException(status_code=400, detail=f"Unsupported period: {period!r}")


@router.get(
    "/by-tenant",
    response_model=List[TenantUsageSummary],
    summary="List usage aggregated by tenant and environment",
)
async def get_usage_by_tenant(
    start: Optional[str] = Query(
        None,
        description="Start datetime in ISO 8601 (inclusive)",
    ),
    end: Optional[str] = Query(
        None,
        description="End datetime in ISO 8601 (exclusive)",
    ),
    tenant_id: Optional[str] = Query(
        None,
        description="Optional tenant_id filter; if omitted, all tenants are returned.",
    ),
    session: Any = Depends(get_db_session),
) -> List[TenantUsageSummary]:
    """
    Return aggregated usage per tenant for the admin Billing & Usage screen.

    When the DB / SQLAlchemy stack is unavailable, get_db_session will raise 503
    and the enterprise console will show a friendly "usage not configured" state.
    """
    start_dt = _parse_iso8601_or_none(start)
    end_dt = _parse_iso8601_or_none(end)

    tenant_ids = [tenant_id] if tenant_id else None

    rows = await decisions_store.aggregate_usage_by_tenant(
        session,
        start=start_dt,
        end=end_dt,
        tenant_ids=tenant_ids,
    )

    return [
        TenantUsageSummary(
            tenant_id=row.tenant_id,
            environment=row.environment,
            total=row.total,
            allow=row.allow,
            block=row.block,
            clarify=row.clarify,
            total_tokens=row.total_tokens,
            first_seen_at=row.first_seen_at,
            last_seen_at=row.last_seen_at,
        )
        for row in rows
    ]


@router.get(
    "/export",
    summary="Export usage by tenant as CSV",
)
async def export_usage_by_tenant_csv(
    start: Optional[str] = Query(
        None,
        description="Start datetime in ISO 8601 (inclusive)",
    ),
    end: Optional[str] = Query(
        None,
        description="End datetime in ISO 8601 (exclusive)",
    ),
    tenant_id: Optional[str] = Query(
        None,
        description="Optional tenant_id filter for a single tenant",
    ),
    session: Any = Depends(get_db_session),
) -> Response:
    """
    Export aggregated usage by tenant as CSV for offline billing / analysis.
    """
    start_dt = _parse_iso8601_or_none(start)
    end_dt = _parse_iso8601_or_none(end)
    tenant_ids = [tenant_id] if tenant_id else None

    rows = await decisions_store.aggregate_usage_by_tenant(
        session,
        start=start_dt,
        end=end_dt,
        tenant_ids=tenant_ids,
    )

    buffer = io.StringIO()
    writer = csv.writer(buffer)

    writer.writerow(
        [
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
    )

    for row in rows:
        writer.writerow(
            [
                row.tenant_id,
                row.environment,
                row.total,
                row.allow,
                row.block,
                row.clarify,
                row.total_tokens,
                row.first_seen_at.isoformat() if row.first_seen_at else "",
                row.last_seen_at.isoformat() if row.last_seen_at else "",
            ]
        )

    buffer.seek(0)

    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": (
                'attachment; filename="guardrail-usage-by-tenant.csv"'
            )
        },
    )


@router.get(
    "/summary",
    response_model=AdminUsagePeriodSummary,
    summary="Summarize usage for a billing period",
)
async def get_usage_summary(
    period: str = Query(
        "30d",
        description="Period key (e.g. '7d', '30d', 'current_month').",
    ),
    tenant_id: Optional[str] = Query(
        None,
        description="Optional tenant_id filter; if omitted, all tenants in the period are included.",
    ),
    session: Any = Depends(get_db_session),
) -> AdminUsagePeriodSummary:
    """
    Return a single summary object for the given billing period, optionally scoped
    to a single tenant.
    """

    start_dt, end_dt = _resolve_period(period)

    tenant_ids = [tenant_id] if tenant_id else None

    row = await decisions_store.aggregate_usage_summary(
        session,
        start=start_dt,
        end=end_dt,
        tenant_ids=tenant_ids,
    )

    return AdminUsagePeriodSummary(
        period=period,
        tenant=tenant_id,
        total=row.total,
        allow=row.allow,
        block=row.block,
        clarify=row.clarify,
        total_tokens=row.total_tokens,
        tenant_count=row.tenant_count,
        environment_count=row.environment_count,
        first_seen_at=row.first_seen_at,
        last_seen_at=row.last_seen_at,
    )


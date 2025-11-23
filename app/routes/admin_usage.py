from __future__ import annotations

import csv
import io
from datetime import datetime
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.dependencies.auth import AdminAuthDependency
from app.dependencies.db import get_db_session
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


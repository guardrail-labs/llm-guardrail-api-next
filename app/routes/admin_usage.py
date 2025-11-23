from __future__ import annotations

import csv
import io
import re
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies.db import get_db_session
from app.routes.admin_rbac import require_admin as require_admin_rbac
from app.schemas.usage import UsageSummary
from app.security.admin_auth import require_admin
from app.services.decisions_store import (
    aggregate_usage_by_tenant,
    summarize_usage,
)

router = APIRouter(tags=["admin-usage"])


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


_SAFE_PERIOD_RE = re.compile(r"[^a-zA-Z0-9_\-]")


def _safe_period_label(period: str) -> str:
    """
    Sanitize period for use in filenames/headers.

    Replaces any character outside [a-zA-Z0-9_-] with '_'.
    """
    return _SAFE_PERIOD_RE.sub("_", period)


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


@router.get(
    "/admin/api/usage/export",
    response_class=StreamingResponse,
    summary="Export decision usage as CSV",
)
async def export_usage_csv(
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
) -> StreamingResponse:
    start, end = _resolve_period(period)

    rows = await aggregate_usage_by_tenant(
        session,
        start=start,
        end=end,
        tenant_ids=tenant_ids,
    )
    summaries = summarize_usage(rows)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        ["tenant_id", "environment", "total", "allow", "block", "clarify"]
    )
    for s in summaries:
        writer.writerow(
            [
                s.tenant_id,
                s.environment,
                s.total,
                s.allow,
                s.block,
                s.clarify,
            ]
        )

    output.seek(0)

    safe_label = _safe_period_label(period)
    filename = f"guardrail-usage-{safe_label}.csv"

    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Content-Type": "text/csv; charset=utf-8",
    }

    return StreamingResponse(output, headers=headers, media_type="text/csv")

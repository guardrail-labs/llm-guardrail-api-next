from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, Iterable, List, Tuple

from app.models.decision import Decision
from app.schemas.usage import UsageRow, UsageSummary


async def aggregate_usage_by_tenant(
    session: Any,
    *,
    start: datetime,
    end: datetime,
    tenant_ids: List[str] | None = None,
) -> List[UsageRow]:
    """
    Aggregate decision counts by tenant, bot, and outcome between [start, end).

    Uses the persisted `decisions` table (tenant, bot, outcome, ts).
    Requires SQLAlchemy to be installed in the environment.
    """
    try:
        from sqlalchemy import func, select  # type: ignore[import-untyped]
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise RuntimeError(
            "SQLAlchemy is required to aggregate usage; "
            "install sqlalchemy to enable this feature."
        ) from exc

    stmt = (
        select(
            Decision.tenant,
            Decision.bot,
            Decision.outcome,
            func.count().label("count"),
        )
        .where(Decision.ts >= start, Decision.ts < end)
        .group_by(Decision.tenant, Decision.bot, Decision.outcome)
    )

    if tenant_ids:
        stmt = stmt.where(Decision.tenant.in_(tenant_ids))

    result = await session.execute(stmt)

    rows: List[UsageRow] = []
    for tenant, bot, outcome, count in result.all():
        rows.append(
            UsageRow(
                tenant_id=tenant,
                environment=bot,
                decision=str(outcome),
                count=int(count),
            )
        )
    return rows


def summarize_usage(rows: Iterable[UsageRow]) -> List[UsageSummary]:
    """
    Reduce UsageRow entries into per-tenant/environment summaries.
    """
    summary: Dict[Tuple[str, str], Dict[str, int]] = defaultdict(
        lambda: {"allow": 0, "block": 0, "clarify": 0}
    )

    for row in rows:
        key = (row.tenant_id, row.environment)
        counts = summary[key]
        decision = row.decision.lower()
        if decision == "allow":
            counts["allow"] += row.count
        elif decision == "block":
            counts["block"] += row.count
        elif decision == "clarify":
            counts["clarify"] += row.count

    result: List[UsageSummary] = []
    for (tenant_id, environment), counts in summary.items():
        total = counts["allow"] + counts["block"] + counts["clarify"]
        result.append(
            UsageSummary(
                tenant_id=tenant_id,
                environment=environment,
                total=total,
                allow=counts["allow"],
                block=counts["block"],
                clarify=counts["clarify"],
            )
        )

    return result


__all__ = ["aggregate_usage_by_tenant", "summarize_usage"]

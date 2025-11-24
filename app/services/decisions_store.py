from __future__ import annotations

from collections.abc import Iterable as IterableABC, Iterator
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Literal, Optional, Sequence, Tuple, TypedDict, cast

try:  # pragma: no cover - optional dependency resolution
    from sqlalchemy import and_, or_, select, case as sa_case
    from sqlalchemy.sql import Select, func, literal
except ModuleNotFoundError:  # pragma: no cover - fallback when SQLAlchemy missing
    and_ = cast(Any, None)
    func = cast(Any, None)
    literal = cast(Any, None)
    or_ = cast(Any, None)
    sa_case = cast(Any, None)
    select = cast(Any, None)
    Select = Any

try:  # pragma: no cover - optional dependency resolution
    from app.services import decisions as decisions_service
except ModuleNotFoundError:  # pragma: no cover - fallback when SQLAlchemy missing
    decisions_service = None  # type: ignore[assignment]

from app.security.rbac import ScopeParam
from app.schemas.usage import UsageRow, UsageSummary
from app.utils.cursor import decode_cursor, encode_cursor


class DecisionRecord(TypedDict, total=False):
    id: str
    ts: datetime
    ts_ms: int
    tenant: str
    bot: str
    outcome: str
    policy_version: str
    rule_id: str
    incident_id: str
    mode: str
    details: Any
    request_id: str


_DECISIONS: List[DecisionRecord] = []


def _get_decision_model() -> Any:
    Decision: Any = getattr(decisions_service, "Decision", None) if decisions_service else None
    if Decision is None:
        try:
            from app.models.decision import Decision as DecisionModel  # type: ignore[import-untyped]

            Decision = DecisionModel
        except ModuleNotFoundError as exc:  # pragma: no cover
            raise RuntimeError("Decision model is unavailable for usage aggregation") from exc

    return Decision


def _resolve_decision_columns() -> Tuple[Any, Any, Any, Any, Any, Any]:
    if decisions_service is None:
        raise RuntimeError("Usage aggregation requires SQLAlchemy and decisions service")

    Decision = _get_decision_model()

    created_column = getattr(Decision, "created_at", None) or getattr(Decision, "ts", None)
    tenant_column = getattr(Decision, "tenant_id", None) or getattr(Decision, "tenant", None)
    environment_column = getattr(Decision, "environment", None) or getattr(Decision, "bot", None)
    outcome_column = getattr(Decision, "outcome", None) or getattr(Decision, "decision", None)
    total_tokens_column = getattr(Decision, "total_tokens", None)

    if tenant_column is None or created_column is None:
        raise RuntimeError("Decision model missing required tenant or timestamp columns")
    if (
        created_column is None
        or tenant_column is None
        or environment_column is None
        or outcome_column is None
    ):
        raise RuntimeError("Decision model is missing required columns for usage aggregation")

    return (
        Decision,
        created_column,
        tenant_column,
        environment_column,
        outcome_column,
        total_tokens_column,
    )


@dataclass
class TenantUsageRow:
    tenant_id: str
    total_requests: int
    allowed_requests: int
    blocked_requests: int
    total_tokens: int
    first_seen_at: Optional[datetime]
    last_seen_at: Optional[datetime]


@dataclass
class TenantEnvUsageRow:
    tenant_id: str
    environment: str
    total: int
    allow: int
    block: int
    clarify: int
    total_tokens: int
    first_seen_at: Optional[datetime]
    last_seen_at: Optional[datetime]


@dataclass
class UsagePeriodSummaryRow:
    total: int
    allow: int
    block: int
    clarify: int
    total_tokens: int
    tenant_count: int
    environment_count: int
    first_seen_at: Optional[datetime]
    last_seen_at: Optional[datetime]


def record_decision(decision: DecisionRecord) -> None:
    _DECISIONS.append(decision)


def iter_decisions() -> Iterator[DecisionRecord]:
    yield from _DECISIONS


def reset_decisions() -> None:
    _DECISIONS.clear()


Dir = Literal["next", "prev"]


def _normalize_scope_values(scope: ScopeParam) -> Optional[List[str]]:
    if scope is None:
        return None
    if isinstance(scope, str):
        return [scope]
    if isinstance(scope, IterableABC) and not isinstance(scope, (str, bytes)):
        values = [str(item) for item in scope if item is not None]
        if not values:
            return []
        # Preserve order while dropping duplicates.
        seen: Dict[str, None] = {}
        for value in values:
            seen.setdefault(value, None)
        return list(seen.keys())
    return [str(scope)]


def list_with_cursor(
    *,
    tenant: ScopeParam = None,
    bot: ScopeParam = None,
    limit: int = 50,
    cursor: Optional[str] = None,
    dir: Dir = "next",
    since_ts_ms: Optional[int] = None,
    outcome: Optional[str] = None,
    request_id: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], Optional[str], Optional[str]]:
    """Return a page of decisions ordered by ``(ts_ms DESC, id DESC)``.

    The ``since_ts_ms``, ``outcome``, and ``request_id`` filters are applied
    against the ordered results before the cursor windowing step so the
    returned page aligns with the cursor semantics.
    """

    safe_limit = max(1, min(int(limit), 500))
    decoded: Optional[Tuple[int, str]] = None
    if cursor:
        decoded = decode_cursor(cursor)

    raw_items = _fetch_decisions_sorted_desc(
        tenant=tenant,
        bot=bot,
        limit=safe_limit + 1,
        cursor=decoded,
        dir=dir,
        since_ts_ms=since_ts_ms,
        outcome=outcome,
        request_id=request_id,
    )

    filtered_items = _apply_filters(
        raw_items,
        since_ts_ms=since_ts_ms,
        outcome=outcome,
        request_id=request_id,
    )
    items = _apply_cursor_window(filtered_items, decoded, dir)
    page = items[:safe_limit]
    if not page:
        return [], None, None

    first = page[0]
    last = page[-1]
    next_cursor_token: Optional[str] = encode_cursor(int(last["ts_ms"]), str(last["id"]))
    prev_cursor_token: Optional[str] = encode_cursor(int(first["ts_ms"]), str(first["id"]))

    has_more = len(items) > safe_limit
    if dir == "next":
        if cursor is None:
            prev_cursor_token = None
        if not has_more:
            next_cursor_token = None
    else:
        if not has_more:
            prev_cursor_token = None

    return page, next_cursor_token, prev_cursor_token


def _apply_cursor_window(
    items: List[Dict[str, Any]],
    decoded: Optional[Tuple[int, str]],
    dir: Dir,
) -> List[Dict[str, Any]]:
    normalized_items = [_ensure_ts_ms(item) for item in items]
    if decoded is None:
        return normalized_items

    ts_ms, id_value = decoded

    def before(entry: Dict[str, Any]) -> bool:
        key = (int(entry["ts_ms"]), str(entry["id"]))
        return key < (ts_ms, id_value)

    def after(entry: Dict[str, Any]) -> bool:
        key = (int(entry["ts_ms"]), str(entry["id"]))
        return key > (ts_ms, id_value)

    if dir == "next":
        return [item for item in normalized_items if before(item)]
    return [item for item in normalized_items if after(item)]


def _apply_filters(
    items: List[Dict[str, Any]],
    *,
    since_ts_ms: Optional[int],
    outcome: Optional[str],
    request_id: Optional[str],
) -> List[Dict[str, Any]]:
    normalized = [_ensure_ts_ms(item) for item in items]
    return _filter_items(
        normalized,
        since_ts_ms=since_ts_ms,
        outcome=outcome,
        request_id=request_id,
    )


def _filter_items(
    items: List[Dict[str, Any]],
    *,
    since_ts_ms: Optional[int],
    outcome: Optional[str],
    request_id: Optional[str],
) -> List[Dict[str, Any]]:
    if since_ts_ms is None and outcome is None and request_id is None:
        return items

    filtered = items
    if since_ts_ms is not None:
        filtered = [item for item in filtered if int(item["ts_ms"]) >= int(since_ts_ms)]
    if outcome is not None:
        filtered = [item for item in filtered if item.get("outcome") == outcome]
    if request_id is not None:
        filtered = [item for item in filtered if _extract_request_id(item) == request_id]
    return filtered


def _ensure_ts_ms(item: Dict[str, Any]) -> Dict[str, Any]:
    if "ts_ms" in item:
        return item
    ts_val = item.get("ts")
    if isinstance(ts_val, datetime):
        dt = ts_val.astimezone(timezone.utc)
    else:
        dt = datetime.fromtimestamp(0, tz=timezone.utc)
    ts_ms = int(dt.timestamp() * 1000)
    new_item = dict(item)
    new_item["ts_ms"] = ts_ms
    return new_item


def _fetch_decisions_sorted_desc(
    *,
    tenant: ScopeParam,
    bot: ScopeParam,
    limit: int,
    cursor: Optional[Tuple[int, str]],
    dir: Dir,
    since_ts_ms: Optional[int] = None,
    outcome: Optional[str] = None,
    request_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    if select is None or decisions_service is None:
        raise RuntimeError("SQLAlchemy is required for decisions cursor pagination")
    table = decisions_service.decisions
    effective_limit: Optional[int] = limit
    stmt: Select = select(table)
    tenant_values = _normalize_scope_values(tenant)
    bot_values = _normalize_scope_values(bot)
    if tenant_values == [] or bot_values == []:
        return []
    conditions = []
    if tenant_values:
        if len(tenant_values) == 1:
            conditions.append(table.c.tenant == tenant_values[0])
        else:
            conditions.append(table.c.tenant.in_(tenant_values))
    if bot_values:
        if len(bot_values) == 1:
            conditions.append(table.c.bot == bot_values[0])
        else:
            conditions.append(table.c.bot.in_(bot_values))
    if since_ts_ms is not None:
        since_dt = datetime.fromtimestamp(since_ts_ms / 1000, tz=timezone.utc)
        conditions.append(table.c.ts >= since_dt)
    if outcome:
        conditions.append(table.c.outcome == outcome)
    if request_id:
        request_col = getattr(table.c, "request_id", None)
        if request_col is not None:
            conditions.append(request_col == request_id)
        else:
            effective_limit = None
    if cursor is not None:
        ts_ms, cursor_id = cursor
        cursor_dt = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
        if dir == "next":
            conditions.append(
                or_(
                    table.c.ts < cursor_dt,
                    and_(table.c.ts == cursor_dt, table.c.id < cursor_id),
                )
            )
        else:
            conditions.append(
                or_(
                    table.c.ts > cursor_dt,
                    and_(table.c.ts == cursor_dt, table.c.id > cursor_id),
                )
            )
    if conditions:
        stmt = stmt.where(and_(*conditions))
    stmt = stmt.order_by(table.c.ts.desc(), table.c.id.desc())
    if effective_limit is not None:
        stmt = stmt.limit(max(effective_limit, 1))
    with decisions_service._get_engine().begin() as conn:
        rows = list(conn.execute(stmt).mappings())
    return [_row_to_item(row) for row in rows]


def _extract_request_id(item: Dict[str, Any]) -> Optional[str]:
    raw = item.get("request_id")
    if isinstance(raw, str) and raw:
        return raw
    details = item.get("details")
    if isinstance(details, dict):
        nested = details.get("request_id")
        if nested is None:
            return None
        if isinstance(nested, str):
            return nested or None
        return str(nested)
    return None


def _row_to_item(row: Any) -> Dict[str, Any]:
    if decisions_service is None:
        raise RuntimeError("SQLAlchemy is required for decisions cursor pagination")

    item = decisions_service._to_item(row)
    ts_val = item.get("ts")
    if isinstance(ts_val, datetime):
        dt = ts_val.astimezone(timezone.utc)
        item["ts_ms"] = int(dt.timestamp() * 1000)
    return item


async def aggregate_usage_by_tenant(
    session: Any,
    *,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    tenant_ids: Optional[Iterable[str]] = None,
) -> List[TenantEnvUsageRow]:
    """
    Aggregate decision traffic by tenant + environment for billing / usage screens.

    This is intentionally DB-backed only. When SQLAlchemy is not present, callers
    should see a 503 via the dependency layer rather than use this function.
    """

    if (
        select is None
        or decisions_service is None
        or sa_case is None
        or func is None
        or literal is None
    ):
        raise RuntimeError(
            "Usage aggregation requires SQLAlchemy and decisions service",
        )

    (
        Decision,
        created_column,
        tenant_column,
        environment_column,
        outcome_column,
        total_tokens_column,
    ) = _resolve_decision_columns()

    case = sa_case

    conditions: list[Any] = []
    if start is not None:
        conditions.append(created_column >= start)
    if end is not None:
        conditions.append(created_column < end)
    if tenant_ids:
        conditions.append(tenant_column.in_(list(tenant_ids)))

    stmt = (
        select(
            tenant_column.label("tenant_id"),
            environment_column.label("environment"),
            func.count(Decision.id).label("total"),
            func.sum(case((outcome_column == "allow", 1), else_=0)).label("allow"),
            func.sum(case((outcome_column == "block", 1), else_=0)).label("block"),
            func.sum(case((outcome_column == "clarify", 1), else_=0)).label("clarify"),
            (
                func.coalesce(func.sum(total_tokens_column), 0)
                if total_tokens_column is not None
                else literal(0)
            ).label("total_tokens"),
            func.min(created_column).label("first_seen_at"),
            func.max(created_column).label("last_seen_at"),
        )
        .where(and_(*conditions) if conditions else True)  # type: ignore[arg-type]
        .group_by(tenant_column, environment_column)
        .order_by(tenant_column, environment_column)
    )

    result = await session.execute(stmt)
    rows: Sequence[Any] = result.fetchall()

    return [
        TenantEnvUsageRow(
            tenant_id=row.tenant_id,
            environment=row.environment,
            total=int(row.total or 0),
            allow=int(row.allow or 0),
            block=int(row.block or 0),
            clarify=int(row.clarify or 0),
            total_tokens=int(row.total_tokens or 0),
            first_seen_at=row.first_seen_at,
            last_seen_at=row.last_seen_at,
        )
        for row in rows
    ]


async def aggregate_usage_summary(
    session: Any,
    *,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    tenant_ids: Optional[Iterable[str]] = None,
) -> UsagePeriodSummaryRow:
    """
    Aggregate decision traffic for a period (optionally scoped to specific tenants).
    """

    if (
        select is None
        or decisions_service is None
        or sa_case is None
        or literal is None
    ):  # type: ignore[truthy-function]
        raise RuntimeError("Usage aggregation requires SQLAlchemy and decisions service")

    (
        _Decision,
        created_column,
        tenant_column,
        environment_column,
        outcome_column,
        total_tokens_column,
    ) = _resolve_decision_columns()

    func = decisions_service.func
    case = sa_case

    conditions: list[Any] = []
    if start is not None:
        conditions.append(created_column >= start)
    if end is not None:
        conditions.append(created_column < end)
    if tenant_ids:
        conditions.append(tenant_column.in_(list(tenant_ids)))

    total_tokens_expr = (
        func.coalesce(func.sum(total_tokens_column), 0)
        if total_tokens_column is not None
        else literal(0)
    )

    stmt = (
        select(
            func.count().label("total"),
            func.sum(case((outcome_column == "allow", 1), else_=0)).label("allow"),
            func.sum(case((outcome_column == "block", 1), else_=0)).label("block"),
            func.sum(case((outcome_column == "clarify", 1), else_=0)).label("clarify"),
            total_tokens_expr.label("total_tokens"),
            func.count(func.distinct(tenant_column)).label("tenant_count"),
            func.count(func.distinct(environment_column)).label("environment_count"),
            func.min(created_column).label("first_seen_at"),
            func.max(created_column).label("last_seen_at"),
        ).where(and_(*conditions) if conditions else True)  # type: ignore[arg-type]
    )

    result = await session.execute(stmt)
    row = result.one()

    return UsagePeriodSummaryRow(
        total=int(row.total or 0),
        allow=int(row.allow or 0),
        block=int(row.block or 0),
        clarify=int(row.clarify or 0),
        total_tokens=int(row.total_tokens or 0),
        tenant_count=int(row.tenant_count or 0),
        environment_count=int(row.environment_count or 0),
        first_seen_at=row.first_seen_at,
        last_seen_at=row.last_seen_at,
    )


def summarize_usage(rows: IterableABC[UsageRow]) -> List[UsageSummary]:
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


__all__ = [
    "DecisionRecord",
    "record_decision",
    "iter_decisions",
    "reset_decisions",
    "TenantUsageRow",
    "TenantEnvUsageRow",
    "UsagePeriodSummaryRow",
    "list_with_cursor",
    "aggregate_usage_by_tenant",
    "aggregate_usage_summary",
    "summarize_usage",
]

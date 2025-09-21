from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Iterable, Optional, cast


def _decisions_supports_sql() -> bool:
    try:
        import sqlalchemy  # noqa: F401

        from app.services import decisions as _decisions  # noqa: F401
    except Exception:  # pragma: no cover - optional dependency guard
        return False
    return True


def _cutoff_dt(cutoff_ms: int) -> datetime:
    cutoff = max(int(cutoff_ms), 0)
    return datetime.fromtimestamp(cutoff / 1000.0, tz=timezone.utc)


def _decision_matches(entry: dict, cutoff_ms: int) -> bool:
    try:
        ts = int(entry.get("ts_ms") or 0)
    except Exception:
        ts = 0
    return ts < cutoff_ms


def _iter_decision_items(
    cutoff_ms: int,
    *,
    tenant: Optional[str],
    bot: Optional[str],
    limit: int,
) -> Iterable[dict]:
    from app.services import decisions_store as store

    fetch = cast(
        Callable[..., Iterable[dict]],
        getattr(store, "_fetch_decisions_sorted_desc"),
    )
    try:
        items = fetch(
            tenant=tenant,
            bot=bot,
            limit=max(limit, 1),
            cursor=None,
            dir="next",
        )
    except TypeError:  # pragma: no cover - fallback for shims
        items = fetch(tenant=tenant, bot=bot)
    return list(items)


def count_decisions_before(
    cutoff_ms: int,
    *,
    tenant: Optional[str],
    bot: Optional[str],
) -> int:
    if _decisions_supports_sql():  # pragma: no branch - runtime check
        try:
            from sqlalchemy import and_, func, select

            from app.services import decisions as decisions_service

            table = decisions_service.decisions
            cutoff_dt = _cutoff_dt(cutoff_ms)
            conditions = [table.c.ts < cutoff_dt]
            if tenant:
                conditions.append(table.c.tenant == tenant)
            if bot:
                conditions.append(table.c.bot == bot)
            stmt = select(func.count()).select_from(table).where(and_(*conditions))
            with decisions_service._get_engine().begin() as conn:
                result = conn.execute(stmt).scalar_one()
            return int(result or 0)
        except Exception:
            pass

    count = 0
    for entry in _iter_decision_items(cutoff_ms, tenant=tenant, bot=bot, limit=50000):
        if _decision_matches(entry, cutoff_ms):
            count += 1
    return count


def delete_decisions_before(
    cutoff_ms: int,
    *,
    tenant: Optional[str],
    bot: Optional[str],
    limit: int,
) -> int:
    if limit <= 0:
        return 0

    if _decisions_supports_sql():
        try:
            from sqlalchemy import and_, delete, select

            from app.services import decisions as decisions_service

            table = decisions_service.decisions
            cutoff_dt = _cutoff_dt(cutoff_ms)
            conditions = [table.c.ts < cutoff_dt]
            if tenant:
                conditions.append(table.c.tenant == tenant)
            if bot:
                conditions.append(table.c.bot == bot)
            stmt = (
                select(table.c.id)
                .where(and_(*conditions))
                .order_by(table.c.ts.asc(), table.c.id.asc())
                .limit(limit)
            )
            with decisions_service._get_engine().begin() as conn:
                ids = [row.id for row in conn.execute(stmt)]
                if not ids:
                    return 0
                del_stmt = delete(table).where(table.c.id.in_(ids))
                result = conn.execute(del_stmt)
            return int(result.rowcount or 0)
        except Exception:
            pass

    from app.services import decisions_store as store

    items = list(
        _iter_decision_items(
            cutoff_ms,
            tenant=tenant,
            bot=bot,
            limit=max(limit * 2, 50000),
        )
    )
    survivors = []
    removed = 0
    for entry in items:
        if removed >= limit:
            survivors.append(entry)
            continue
        if _decision_matches(entry, cutoff_ms):
            removed += 1
        else:
            survivors.append(entry)
    setter = getattr(store, "_set_decisions_for_tests", None)
    if callable(setter):
        setter(survivors)
    return removed


def count_adjudications_before(
    cutoff_ms: int,
    *,
    tenant: Optional[str],
    bot: Optional[str],
) -> int:
    from app.observability import adjudication_log as log

    cutoff_dt = _cutoff_dt(cutoff_ms)
    try:
        _, total = log.paged_query(
            end=cutoff_dt,
            tenant=tenant,
            bot=bot,
            limit=0,
            offset=0,
            sort="ts_desc",
        )
        return int(total)
    except Exception:
        return 0


def delete_adjudications_before(
    cutoff_ms: int,
    *,
    tenant: Optional[str],
    bot: Optional[str],
    limit: int,
) -> int:
    if limit <= 0:
        return 0

    from app.observability import adjudication_log as log

    cutoff = cutoff_ms
    try:
        cap = int(getattr(log, "_CAP", 10000))
    except Exception:
        cap = 10000

    try:
        records, _ = log.paged_query(
            tenant=None,
            bot=None,
            limit=cap,
            offset=0,
            sort="ts_asc",
        )
    except Exception:
        records = []

    kept = []
    removed = 0
    for record in records:
        ts_val = log._record_ts_ms(record) if hasattr(log, "_record_ts_ms") else 0
        match_tenant = tenant is None or getattr(record, "tenant", None) == tenant
        match_bot = bot is None or getattr(record, "bot", None) == bot
        if removed < limit and match_tenant and match_bot and ts_val < cutoff:
            removed += 1
            continue
        kept.append(record)

    if removed and hasattr(log, "clear") and hasattr(log, "append"):
        log.clear()
        for entry in kept:
            log.append(entry)
    return removed

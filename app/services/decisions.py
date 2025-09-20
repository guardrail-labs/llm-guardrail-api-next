from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from sqlalchemy import (
    Column,
    DateTime,
    Index,
    MetaData,
    String,
    Table,
    Text,
    create_engine,
    insert,
    select,
    text,
)
from sqlalchemy.sql import and_, func

from app.observability.metrics import mitigation_override_counter
from app.services.mitigation_prefs import Mode, resolve_mode, validate_mode

# Import SQLAlchemy types only during type checking to avoid runtime/type-assign errors
if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------

_DEFAULT_DSN = os.getenv("DECISIONS_DSN", "sqlite:///./data/decisions.db")
_AUTOCREATE = os.getenv("DECISIONS_AUTOCREATE", "true").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)
_PRUNE_DAYS = int(os.getenv("DECISIONS_PRUNE_DAYS", "30"))

_engine_instance: Optional["Engine"] = None
_meta = MetaData()

# JSON-as-TEXT (cross-dialect)
decisions = Table(
    "decisions",
    _meta,
    Column("id", String(64), primary_key=True),
    Column("ts", DateTime(timezone=True), nullable=False, index=True),
    Column("tenant", String(128), nullable=False, index=True),
    Column("bot", String(128), nullable=False, index=True),
    Column("outcome", String(64), nullable=False, index=True),
    Column("policy_version", String(128), nullable=True),
    Column("rule_id", String(256), nullable=True),
    Column("incident_id", String(128), nullable=True, index=True),
    Column("mode", String(32), nullable=True),
    Column("details", Text, nullable=True),  # JSON-encoded
)

# Helpful composite indexes
Index(
    "ix_decisions_tenant_bot_ts",
    decisions.c.tenant,
    decisions.c.bot,
    decisions.c.ts.desc(),
)
Index("ix_decisions_outcome_ts", decisions.c.outcome, decisions.c.ts.desc())


# -----------------------------------------------------------------------------
# Internals
# -----------------------------------------------------------------------------
def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _get_engine() -> "Engine":
    """
    Lazily create and cache the SQLAlchemy engine.
    Creates the SQLite directory on first use if needed.
    """
    global _engine_instance
    if _engine_instance is not None:
        return _engine_instance

    dsn = _DEFAULT_DSN

    # If using local SQLite, ensure the directory exists.
    if dsn.startswith("sqlite:///"):
        path = dsn.replace("sqlite:///", "", 1)
        dir_ = os.path.dirname(path or ".")
        if dir_:
            os.makedirs(dir_, exist_ok=True)

    eng = create_engine(dsn, future=True, pool_pre_ping=True)
    if _AUTOCREATE:
        _meta.create_all(eng)

    _engine_instance = eng
    return eng


def _to_item(row: Any) -> Dict[str, Any]:
    """
    Convert a RowMapping/row-like object to a plain dict
    without importing SQLAlchemy row types at runtime.
    """
    return {
        "id": row.id,
        "ts": row.ts,
        "tenant": row.tenant,
        "bot": row.bot,
        "outcome": row.outcome,
        "policy_version": row.policy_version,
        "rule_id": row.rule_id,
        "incident_id": row.incident_id,
        "mode": row.mode,
        "details": json.loads(row.details) if row.details else None,
    }


# Map API sort keys to SQLAlchemy columns
_SORT_MAP = {
    "ts": decisions.c.ts,
    "tenant": decisions.c.tenant,
    "bot": decisions.c.bot,
    "outcome": decisions.c.outcome,
    "policy_version": decisions.c.policy_version,
    "rule_id": decisions.c.rule_id,
    "incident_id": decisions.c.incident_id,
}


# -----------------------------------------------------------------------------
# Public API (auto-detected by admin_decisions_api)
# -----------------------------------------------------------------------------
def query(
    since: Optional[datetime],
    tenant: Optional[str],
    bot: Optional[str],
    outcome: Optional[str],
    limit: int,
    offset: int,
    sort_key: str = "ts",
    sort_dir: str = "desc",
) -> Tuple[List[Dict[str, Any]], Optional[int]]:
    """
    Return (items, total). Server-side sorting with whitelist.
    Compatible with the provider signature expected by admin_decisions_api.
    """
    eng = _get_engine()

    where_clauses = []
    if since is not None:
        where_clauses.append(decisions.c.ts >= since)
    if tenant:
        where_clauses.append(decisions.c.tenant == tenant)
    if bot:
        where_clauses.append(decisions.c.bot == bot)
    if outcome:
        where_clauses.append(decisions.c.outcome == outcome)

    base_select = select(decisions)
    if where_clauses:
        base_select = base_select.where(and_(*where_clauses))
    sort_col = _SORT_MAP.get(str(sort_key or "").lower(), decisions.c.ts)
    sort_dir_norm = str(sort_dir or "desc").lower()
    primary_order = sort_col.asc() if sort_dir_norm == "asc" else sort_col.desc()
    order_by = [primary_order, decisions.c.id.asc()]
    stmt = base_select.order_by(*order_by).offset(offset).limit(limit)

    total_stmt = select(func.count()).select_from(decisions)
    if where_clauses:
        total_stmt = total_stmt.where(and_(*where_clauses))

    with eng.begin() as cx:
        rows = list(cx.execute(stmt).mappings())
        total = cx.execute(total_stmt).scalar_one()

    return [_to_item(r) for r in rows], int(total)


def list_decisions(
    *,
    since: Optional[datetime] = None,
    tenant: Optional[str] = None,
    bot: Optional[str] = None,
    outcome: Optional[str] = None,
    page: int = 1,
    page_size: int = 50,
    sort_key: str = "ts",
    sort_dir: str = "desc",
) -> Tuple[List[Dict[str, Any]], Optional[int]]:
    offset = max(page - 1, 0) * page_size
    return query(
        since=since,
        tenant=tenant,
        bot=bot,
        outcome=outcome,
        limit=page_size,
        offset=offset,
        sort_key=sort_key,
        sort_dir=sort_dir,
    )


def record(
    *,
    id: str,
    ts: Optional[datetime] = None,
    tenant: str = "unknown",
    bot: str = "unknown",
    outcome: str,
    policy_version: Optional[str] = None,
    rule_id: Optional[str] = None,
    incident_id: Optional[str] = None,
    mode: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Insert a single decision row.
    """
    payload = {
        "id": id,
        "ts": ts or _utcnow(),
        "tenant": tenant,
        "bot": bot,
        "outcome": outcome,
        "policy_version": policy_version,
        "rule_id": rule_id,
        "incident_id": incident_id,
        "mode": mode,
        "details": json.dumps(details or {}, separators=(",", ":"), ensure_ascii=False),
    }
    with _get_engine().begin() as cx:
        cx.execute(insert(decisions).values(**payload))


def prune(older_than_days: Optional[int] = None) -> int:
    """
    Delete rows older than N days. Returns deleted row count.
    """
    days = int(_PRUNE_DAYS if older_than_days is None else older_than_days)
    cutoff = _utcnow() - timedelta(days=days)
    with _get_engine().begin() as cx:
        res = cx.execute(text("DELETE FROM decisions WHERE ts < :cutoff"), {"cutoff": cutoff})
        return int(res.rowcount or 0)


def ensure_ready() -> None:
    """
    Initialize the engine/tables on startup if autocreate is enabled.
    """
    eng = _get_engine()
    stmts = (
        "CREATE INDEX IF NOT EXISTS decisions_ts_idx ON decisions(ts)",
        "CREATE INDEX IF NOT EXISTS decisions_tenant_bot_idx ON decisions(tenant, bot)",
        "CREATE INDEX IF NOT EXISTS decisions_outcome_idx ON decisions(outcome)",
    )
    with eng.begin() as conn:
        for raw in stmts:
            try:
                conn.execute(text(raw))
            except Exception:
                continue


def is_force_block_enabled_for_tenant(tenant: str) -> bool:
    """Return True when the global FORCE_BLOCK toggle applies to a tenant."""

    toggle = (os.getenv("FORCE_BLOCK") or "").strip().lower()
    if toggle in {"1", "true", "yes", "on"}:
        return True

    allow_list = os.getenv("FORCE_BLOCK_TENANTS")
    if not allow_list:
        return False

    entries = {item.strip() for item in allow_list.split(",") if item.strip()}
    if not entries:
        return False
    if "*" in entries:
        return True
    return tenant.strip() in entries


def _default_mode(raw: Any) -> Mode:
    text = str(raw or "").strip() or "clarify"
    try:
        return validate_mode(text)
    except ValueError:
        return "clarify"


def _finalize_decision(result: Any, *, tenant: str, bot: str) -> Any:
    """Apply mitigation overrides for the given tenant/bot pair."""

    default_mode = _default_mode(getattr(result, "mitigation", None))
    selected_mode, source = resolve_mode(
        tenant=tenant,
        bot=bot,
        policy_default=default_mode,
    )

    if is_force_block_enabled_for_tenant(tenant):
        if selected_mode != "block":
            mitigation_override_counter.labels(mode="block").inc()
        result.mitigation = "block"
        return result

    if source == "explicit" and selected_mode != default_mode:
        mitigation_override_counter.labels(mode=selected_mode).inc()

    result.mitigation = selected_mode
    return result

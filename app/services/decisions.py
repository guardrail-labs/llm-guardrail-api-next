"""Persistent decision store powered by SQLAlchemy with a SQLite fallback."""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

_DEFAULT_DSN = os.getenv("DECISIONS_DSN", "sqlite:///./data/decisions.db")
_AUTOCREATE = os.getenv("DECISIONS_AUTOCREATE", "true").lower() in {
    "1",
    "true",
    "yes",
    "on",
}
_PRUNE_DAYS = int(os.getenv("DECISIONS_PRUNE_DAYS", "30"))

if TYPE_CHECKING:  # pragma: no cover - help type checkers without runtime cost
    import sqlite3


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


try:  # pragma: no cover - exercised indirectly via integration tests
    from sqlalchemy import (
        Column,
        DateTime,
        Index,
        MetaData,
        String,
        Table,
        Text,
        and_,
        create_engine,
        func,
        insert,
        select,
        text,
    )
    from sqlalchemy.engine import Engine
    from sqlalchemy.engine.row import RowMapping
except ModuleNotFoundError:  # pragma: no cover - fallback used when SQLAlchemy unavailable
    Engine = Any
    RowMapping = Any
    SQLALCHEMY_AVAILABLE = False
else:
    SQLALCHEMY_AVAILABLE = True


class _SqlAlchemyAdapter:
    def __init__(self) -> None:
        self._engine: Engine | None = None
        self._metadata = MetaData()
        self.table = Table(
            "decisions",
            self._metadata,
            Column("id", String(64), primary_key=True),
            Column("ts", DateTime(timezone=True), nullable=False, index=True),
            Column("tenant", String(128), nullable=False, index=True),
            Column("bot", String(128), nullable=False, index=True),
            Column("outcome", String(64), nullable=False, index=True),
            Column("policy_version", String(128), nullable=True),
            Column("rule_id", String(256), nullable=True),
            Column("incident_id", String(128), nullable=True, index=True),
            Column("mode", String(32), nullable=True),
            Column("details", Text, nullable=True),
        )
        Index(
            "ix_decisions_tenant_bot_ts",
            self.table.c.tenant,
            self.table.c.bot,
            self.table.c.ts.desc(),
        )
        Index("ix_decisions_outcome_ts", self.table.c.outcome, self.table.c.ts.desc())

    def _engine_obj(self) -> Engine:
        if self._engine is not None:
            return self._engine

        dsn = _DEFAULT_DSN
        if dsn.startswith("sqlite:///"):
            path = dsn.replace("sqlite:///", "", 1)
            directory = os.path.dirname(path) or "."
            os.makedirs(directory, exist_ok=True)

        engine = create_engine(dsn, future=True, pool_pre_ping=True)
        if _AUTOCREATE:
            self._metadata.create_all(engine)
        self._engine = engine
        return engine

    def ensure_ready(self) -> None:
        self._engine_obj()

    def _row_to_item(self, row: RowMapping) -> Dict[str, Any]:
        ts_value = row["ts"]
        ts_serialized = ts_value.isoformat() if isinstance(ts_value, datetime) else str(ts_value)
        details_raw = row.get("details")
        details_data = json.loads(details_raw) if details_raw else None
        shadow_action = None
        shadow_rule_ids = None
        if isinstance(details_data, dict):
            shadow_action = details_data.get("shadow_action")
            shadow_rule_ids = details_data.get("shadow_rule_ids")
        return {
            "id": row["id"],
            "ts": ts_serialized,
            "tenant": row["tenant"],
            "bot": row["bot"],
            "outcome": row["outcome"],
            "policy_version": row.get("policy_version"),
            "rule_id": row.get("rule_id"),
            "incident_id": row.get("incident_id"),
            "mode": row.get("mode"),
            "details": details_data,
            "shadow_action": shadow_action,
            "shadow_rule_ids": shadow_rule_ids,
        }

    def query(
        self,
        since: Optional[datetime],
        tenant: Optional[str],
        bot: Optional[str],
        outcome: Optional[str],
        limit: int,
        offset: int,
    ) -> Tuple[List[Dict[str, Any]], Optional[int]]:
        engine = self._engine_obj()
        where_clauses = []
        if since is not None:
            where_clauses.append(self.table.c.ts >= since)
        if tenant:
            where_clauses.append(self.table.c.tenant == tenant)
        if bot:
            where_clauses.append(self.table.c.bot == bot)
        if outcome:
            where_clauses.append(self.table.c.outcome == outcome)

        stmt = select(self.table)
        if where_clauses:
            stmt = stmt.where(and_(*where_clauses))
        stmt = stmt.order_by(self.table.c.ts.desc()).offset(offset).limit(limit)

        total_stmt = select(func.count()).select_from(self.table)
        if where_clauses:
            total_stmt = total_stmt.where(and_(*where_clauses))

        with engine.begin() as conn:
            rows = list(conn.execute(stmt).mappings())
            total = conn.execute(total_stmt).scalar_one()

        return [self._row_to_item(row) for row in rows], int(total)

    def record(
        self,
        *,
        id: str,
        ts: Optional[datetime] = None,
        tenant: str,
        bot: str,
        outcome: str,
        policy_version: Optional[str],
        rule_id: Optional[str],
        incident_id: Optional[str],
        mode: Optional[str],
        details: Optional[Dict[str, Any]],
    ) -> None:
        engine = self._engine_obj()
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
        with engine.begin() as conn:
            conn.execute(insert(self.table).values(**payload))

    def prune(self, older_than_days: Optional[int]) -> int:
        days = int(_PRUNE_DAYS if older_than_days is None else older_than_days)
        cutoff = _utcnow() - timedelta(days=days)
        engine = self._engine_obj()
        with engine.begin() as conn:
            result = conn.execute(
                text("DELETE FROM decisions WHERE ts < :cutoff"),
                {"cutoff": cutoff},
            )
        return int(result.rowcount or 0)


class _SQLiteFallbackAdapter:
    def __init__(self) -> None:
        self._conn: "sqlite3.Connection" | None = None

    def _path(self) -> str:
        if not _DEFAULT_DSN.startswith("sqlite:///"):
            raise RuntimeError("SQLite fallback requires a sqlite:/// DSN")
        path = _DEFAULT_DSN.replace("sqlite:///", "", 1)
        return path or "./decisions.db"

    def _connection(self) -> "sqlite3.Connection":
        import sqlite3

        if self._conn is not None:
            return self._conn

        path = self._path()
        directory = os.path.dirname(path) or "."
        os.makedirs(directory, exist_ok=True)
        conn = sqlite3.connect(
            path,
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        if _AUTOCREATE:
            self._ensure_schema(conn)
        self._conn = conn
        return conn

    def _ensure_schema(self, conn: "sqlite3.Connection") -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS decisions (
                id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                tenant TEXT NOT NULL,
                bot TEXT NOT NULL,
                outcome TEXT NOT NULL,
                policy_version TEXT,
                rule_id TEXT,
                incident_id TEXT,
                mode TEXT,
                details TEXT
            )
            """
        )
        conn.execute(
            (
                "CREATE INDEX IF NOT EXISTS ix_decisions_tenant_bot_ts "
                "ON decisions (tenant, bot, ts DESC)"
            )
        )
        conn.execute(
            (
                "CREATE INDEX IF NOT EXISTS ix_decisions_outcome_ts "
                "ON decisions (outcome, ts DESC)"
            )
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_decisions_incident ON decisions (incident_id)"
        )
        conn.commit()

    def ensure_ready(self) -> None:
        conn = self._connection()
        if _AUTOCREATE:
            self._ensure_schema(conn)

    def _row_to_item(self, row: "sqlite3.Row") -> Dict[str, Any]:
        ts_value = row["ts"]
        ts_serialized = ts_value if isinstance(ts_value, str) else str(ts_value)
        details_raw = row["details"]
        details_data = json.loads(details_raw) if details_raw else None
        shadow_action = None
        shadow_rule_ids = None
        if isinstance(details_data, dict):
            shadow_action = details_data.get("shadow_action")
            shadow_rule_ids = details_data.get("shadow_rule_ids")
        return {
            "id": row["id"],
            "ts": ts_serialized,
            "tenant": row["tenant"],
            "bot": row["bot"],
            "outcome": row["outcome"],
            "policy_version": row["policy_version"],
            "rule_id": row["rule_id"],
            "incident_id": row["incident_id"],
            "mode": row["mode"],
            "details": details_data,
            "shadow_action": shadow_action,
            "shadow_rule_ids": shadow_rule_ids,
        }

    def record(
        self,
        *,
        id: str,
        ts: Optional[datetime] = None,
        tenant: str,
        bot: str,
        outcome: str,
        policy_version: Optional[str],
        rule_id: Optional[str],
        incident_id: Optional[str],
        mode: Optional[str],
        details: Optional[Dict[str, Any]],
    ) -> None:
        conn = self._connection()
        payload = {
            "id": id,
            "ts": (ts or _utcnow()).isoformat(),
            "tenant": tenant,
            "bot": bot,
            "outcome": outcome,
            "policy_version": policy_version,
            "rule_id": rule_id,
            "incident_id": incident_id,
            "mode": mode,
            "details": json.dumps(details or {}, separators=(",", ":"), ensure_ascii=False),
        }
        columns = ", ".join(payload.keys())
        placeholders = ", ".join(["?"] * len(payload))
        conn.execute(
            f"INSERT INTO decisions ({columns}) VALUES ({placeholders})",
            list(payload.values()),
        )
        conn.commit()

    def query(
        self,
        since: Optional[datetime],
        tenant: Optional[str],
        bot: Optional[str],
        outcome: Optional[str],
        limit: int,
        offset: int,
    ) -> Tuple[List[Dict[str, Any]], Optional[int]]:
        conn = self._connection()
        filters = []
        params: List[Any] = []
        if since is not None:
            filters.append("ts >= ?")
            params.append(since.isoformat())
        if tenant:
            filters.append("tenant = ?")
            params.append(tenant)
        if bot:
            filters.append("bot = ?")
            params.append(bot)
        if outcome:
            filters.append("outcome = ?")
            params.append(outcome)
        where_sql = f" WHERE {' AND '.join(filters)}" if filters else ""
        stmt = (
            "SELECT id, ts, tenant, bot, outcome, policy_version, rule_id, "
            "incident_id, mode, details "
            f"FROM decisions{where_sql} ORDER BY ts DESC LIMIT ? OFFSET ?"
        )
        row_params = params + [limit, offset]
        rows = conn.execute(stmt, row_params).fetchall()
        total_stmt = f"SELECT COUNT(*) FROM decisions{where_sql}"
        total = conn.execute(total_stmt, params).fetchone()[0]
        return [self._row_to_item(row) for row in rows], int(total)

    def prune(self, older_than_days: Optional[int]) -> int:
        conn = self._connection()
        days = int(_PRUNE_DAYS if older_than_days is None else older_than_days)
        cutoff = (_utcnow() - timedelta(days=days)).isoformat()
        cursor = conn.execute("DELETE FROM decisions WHERE ts < ?", (cutoff,))
        conn.commit()
        return int(cursor.rowcount or 0)

AdapterType = _SqlAlchemyAdapter | _SQLiteFallbackAdapter

_adapter: AdapterType
decisions: Any | None

if SQLALCHEMY_AVAILABLE:
    _adapter = _SqlAlchemyAdapter()
    decisions = _adapter.table
else:  # pragma: no cover - fallback exercised in environments without SQLAlchemy
    _adapter = _SQLiteFallbackAdapter()
    decisions = None

__all__ = ["ensure_ready", "prune", "query", "record", "decisions"]


def ensure_ready() -> None:
    _adapter.ensure_ready()


def query(
    since: Optional[datetime],
    tenant: Optional[str],
    bot: Optional[str],
    outcome: Optional[str],
    limit: int,
    offset: int,
) -> Tuple[List[Dict[str, Any]], Optional[int]]:
    return _adapter.query(since, tenant, bot, outcome, limit, offset)


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
    _adapter.record(
        id=id,
        ts=ts,
        tenant=tenant,
        bot=bot,
        outcome=outcome,
        policy_version=policy_version,
        rule_id=rule_id,
        incident_id=incident_id,
        mode=mode,
        details=details,
    )


def prune(older_than_days: Optional[int] = None) -> int:
    return _adapter.prune(older_than_days)

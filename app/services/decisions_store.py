from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Tuple, cast

try:  # pragma: no cover - optional dependency resolution
    from sqlalchemy import and_, or_, select
    from sqlalchemy.sql import Select
except ModuleNotFoundError:  # pragma: no cover - fallback when SQLAlchemy missing
    and_ = cast(Any, None)
    or_ = cast(Any, None)
    select = cast(Any, None)
    Select = Any

try:  # pragma: no cover - optional dependency resolution
    from app.services import decisions as decisions_service
except ModuleNotFoundError:  # pragma: no cover - fallback when SQLAlchemy missing
    decisions_service = None  # type: ignore[assignment]

from app.utils.cursor import decode_cursor, encode_cursor

Dir = Literal["next", "prev"]


def list_with_cursor(
    *,
    tenant: Optional[str] = None,
    bot: Optional[str] = None,
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
        filtered = [
            item for item in filtered if _extract_request_id(item) == request_id
        ]
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
    tenant: Optional[str],
    bot: Optional[str],
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
    stmt: Select = select(table)
    conditions = []
    if tenant:
        conditions.append(table.c.tenant == tenant)
    if bot:
        conditions.append(table.c.bot == bot)
    if since_ts_ms is not None:
        since_dt = datetime.fromtimestamp(since_ts_ms / 1000, tz=timezone.utc)
        conditions.append(table.c.ts >= since_dt)
    if outcome:
        conditions.append(table.c.outcome == outcome)
    if request_id:
        request_col = getattr(table.c, "request_id", None)
        if request_col is not None:
            conditions.append(request_col == request_id)
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
    stmt = stmt.order_by(table.c.ts.desc(), table.c.id.desc()).limit(max(limit, 1))
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

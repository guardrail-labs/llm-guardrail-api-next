from __future__ import annotations

import base64
import json
import os
import threading
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Deque, Iterator, List, Literal, Optional, Sequence, Tuple, Union

from app.utils.cursor import CursorError


def _now_ts() -> str:
    """Return current UTC timestamp as RFC3339 string."""

    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _parse_ts(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _coerce_cap(raw: Optional[str]) -> int:
    try:
        cap = int(raw) if raw else 0
    except Exception:
        cap = 0
    return max(cap, 1) if cap else 10000


@dataclass
class AdjudicationRecord:
    ts: str
    request_id: str
    tenant: str
    bot: str
    provider: str
    decision: str
    rule_hits: List[str]
    score: Optional[float]
    latency_ms: int
    policy_version: Optional[str]
    rules_path: Optional[str]
    sampled: bool
    prompt_sha256: Optional[str]
    rule_id: Optional[str] = None

    def to_dict(self) -> dict:
        data = asdict(self)
        if data.get("rule_id") is None:
            data.pop("rule_id", None)
        mitigation_forced = getattr(self, "mitigation_forced", None)
        if mitigation_forced is not None:
            data["mitigation_forced"] = mitigation_forced
        return data


_CAP = _coerce_cap(os.getenv("ADJUDICATION_LOG_CAP"))
_BUFFER: Deque[AdjudicationRecord] = deque(maxlen=_CAP)
_LOCK = threading.Lock()


def _ts_sort_key(record: AdjudicationRecord) -> datetime:
    parsed = _parse_ts(record.ts)
    if parsed is None:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    return parsed


def _matches(
    record: AdjudicationRecord,
    *,
    start: Optional[datetime],
    end: Optional[datetime],
    tenant: Optional[str],
    bot: Optional[str],
    provider: Optional[str],
    request_id: Optional[str],
    rule_id: Optional[str],
    decision: Optional[str],
    mitigation_forced: Optional[str],
) -> bool:
    if tenant and record.tenant != tenant:
        return False
    if bot and record.bot != bot:
        return False
    if provider and record.provider != provider:
        return False
    if request_id and record.request_id != request_id:
        return False
    if rule_id:
        record_rule_id = getattr(record, "rule_id", None)
        record_rule_hits = getattr(record, "rule_hits", None) or []
        if record_rule_id != rule_id and rule_id not in record_rule_hits:
            return False
    if decision and record.decision != decision:
        return False
    if mitigation_forced is not None:
        record_forced = getattr(record, "mitigation_forced", None)
        if mitigation_forced:
            if record_forced != mitigation_forced:
                return False
        else:
            if record_forced not in (None, ""):
                return False

    ts_dt = _parse_ts(record.ts)
    if start and ts_dt and ts_dt < start:
        return False
    if end and ts_dt and ts_dt >= end:
        return False
    return True


def append(record: AdjudicationRecord) -> None:
    """Best-effort append; never raises."""

    try:
        with _LOCK:
            _BUFFER.append(record)
    except Exception:
        return


def clear() -> None:
    """Clear all buffered records (testing/support)."""

    try:
        with _LOCK:
            _BUFFER.clear()
    except Exception:
        return


def _iter_filtered(
    *,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    tenant: Optional[str] = None,
    bot: Optional[str] = None,
    provider: Optional[str] = None,
    request_id: Optional[str] = None,
    rule_id: Optional[str] = None,
    decision: Optional[str] = None,
    mitigation_forced: Optional[str] = None,
    sort: str = "ts_desc",
) -> Iterator[AdjudicationRecord]:
    with _LOCK:
        snapshot: Sequence[AdjudicationRecord] = list(_BUFFER)

    reverse = sort != "ts_asc"
    ordered = sorted(
        enumerate(snapshot),
        key=lambda item: (_ts_sort_key(item[1]), item[0]),
        reverse=reverse,
    )

    for _, rec in ordered:
        if _matches(
            rec,
            start=start,
            end=end,
            tenant=tenant,
            bot=bot,
            provider=provider,
            request_id=request_id,
            rule_id=rule_id,
            decision=decision,
            mitigation_forced=mitigation_forced,
        ):
            yield rec


def iter_records(
    *,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    tenant: Optional[str] = None,
    bot: Optional[str] = None,
    provider: Optional[str] = None,
    request_id: Optional[str] = None,
    rule_id: Optional[str] = None,
    decision: Optional[str] = None,
    mitigation_forced: Optional[str] = None,
    sort: str = "ts_desc",
) -> Iterator[AdjudicationRecord]:
    yield from _iter_filtered(
        start=start,
        end=end,
        tenant=tenant,
        bot=bot,
        provider=provider,
        request_id=request_id,
        rule_id=rule_id,
        decision=decision,
        mitigation_forced=mitigation_forced,
        sort=sort,
    )


def paged_query(
    *,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    tenant: Optional[str] = None,
    bot: Optional[str] = None,
    provider: Optional[str] = None,
    request_id: Optional[str] = None,
    rule_id: Optional[str] = None,
    decision: Optional[str] = None,
    mitigation_forced: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    sort: str = "ts_desc",
) -> tuple[List[AdjudicationRecord], int]:
    items: List[AdjudicationRecord] = []
    total = 0
    max_index = offset + limit

    for rec in _iter_filtered(
        start=start,
        end=end,
        tenant=tenant,
        bot=bot,
        provider=provider,
        request_id=request_id,
        rule_id=rule_id,
        decision=decision,
        mitigation_forced=mitigation_forced,
        sort=sort,
    ):
        if offset <= total < max_index:
            items.append(rec)
        total += 1

    return items, total




def _record_ts_ms(record: AdjudicationRecord) -> int:
    parsed = _parse_ts(record.ts)
    if parsed is None:
        return 0
    return int(parsed.timestamp() * 1000)


def _enc_cursor(ts_ms: int, idx: int) -> str:
    payload = {"ts": int(ts_ms), "i": int(idx)}
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _dec_cursor(token: str) -> tuple[int, int]:
    if not token:
        raise CursorError("empty cursor")
    pad = "=" * (-len(token) % 4)
    try:
        raw = base64.urlsafe_b64decode((token + pad).encode("ascii"))
        obj = json.loads(raw.decode("utf-8"))
        ts_ms = int(obj["ts"])
        idx = int(obj["i"])
    except Exception as exc:  # pragma: no cover - normalization path
        raise CursorError(f"invalid cursor: {exc}") from exc
    return ts_ms, idx


def _iter_filtered_with_index(
    *,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    tenant: Optional[str] = None,
    bot: Optional[str] = None,
    provider: Optional[str] = None,
    request_id: Optional[str] = None,
    rule_id: Optional[str] = None,
    decision: Optional[str] = None,
    mitigation_forced: Optional[str] = None,
    sort: str = "ts_desc",
) -> Iterator[Tuple[int, AdjudicationRecord]]:
    with _LOCK:
        snapshot: Sequence[AdjudicationRecord] = list(_BUFFER)

    reverse = sort != "ts_asc"
    ordered = sorted(
        enumerate(snapshot),
        key=lambda item: (_ts_sort_key(item[1]), item[0]),
        reverse=reverse,
    )

    for idx, rec in ordered:
        if _matches(
            rec,
            start=start,
            end=end,
            tenant=tenant,
            bot=bot,
            provider=provider,
            request_id=request_id,
            rule_id=rule_id,
            decision=decision,
            mitigation_forced=mitigation_forced,
        ):
            yield idx, rec


def list_with_cursor(
    *,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    tenant: Optional[str] = None,
    bot: Optional[str] = None,
    provider: Optional[str] = None,
    request_id: Optional[str] = None,
    rule_id: Optional[str] = None,
    decision: Optional[str] = None,
    mitigation_forced: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
    dir: Literal["next", "prev"] = "next",
    sort: str = "ts_desc",
) -> Tuple[List[AdjudicationRecord], Optional[str], Optional[str]]:
    safe_limit = max(1, min(int(limit), 500))
    decoded: Optional[Tuple[int, int]] = None
    if cursor:
        decoded = _dec_cursor(cursor)

    entries: List[Tuple[AdjudicationRecord, int, int]] = []
    for idx, rec in _iter_filtered_with_index(
        start=start,
        end=end,
        tenant=tenant,
        bot=bot,
        provider=provider,
        request_id=request_id,
        rule_id=rule_id,
        decision=decision,
        mitigation_forced=mitigation_forced,
        sort="ts_desc",
    ):
        ts_ms = _record_ts_ms(rec)
        if decoded is not None:
            bound_ts, bound_idx = decoded
            if dir == "next":
                if (ts_ms, idx) >= (bound_ts, bound_idx):
                    continue
            else:
                if (ts_ms, idx) <= (bound_ts, bound_idx):
                    continue
        entries.append((rec, ts_ms, idx))
        if len(entries) > safe_limit:
            break

    if not entries:
        return [], None, None

    has_more = len(entries) > safe_limit
    page_entries = entries[:safe_limit]
    first_rec, first_ts, first_idx = page_entries[0]
    last_rec, last_ts, last_idx = page_entries[-1]

    next_cursor_token: Optional[str] = _enc_cursor(last_ts, last_idx)
    prev_cursor_token: Optional[str] = _enc_cursor(first_ts, first_idx)
    if dir == "next":
        if cursor is None:
            prev_cursor_token = None
        if not has_more:
            next_cursor_token = None
    else:
        if not has_more:
            prev_cursor_token = None

    records = [rec for rec, _ts, _idx in page_entries]
    return records, next_cursor_token, prev_cursor_token

def query(
    *,
    start: Optional[str] = None,
    end: Optional[str] = None,
    tenant: Optional[str] = None,
    bot: Optional[str] = None,
    provider: Optional[str] = None,
    request_id: Optional[str] = None,
    rule_id: Optional[str] = None,
    decision: Optional[str] = None,
    mitigation_forced: Optional[str] = None,
    limit: int = 100,
    sort: str = "ts_desc",
) -> List[AdjudicationRecord]:
    try:
        limit_val = int(limit)
    except Exception:
        limit_val = 100
    if limit_val < 1:
        limit_val = 1
    if limit_val > 1000:
        limit_val = 1000

    start_dt = _parse_ts(start) if start else None
    end_dt = _parse_ts(end) if end else None

    items, _ = paged_query(
        start=start_dt,
        end=end_dt,
        tenant=tenant,
        bot=bot,
        provider=provider,
        request_id=request_id,
        rule_id=rule_id,
        decision=decision,
        mitigation_forced=mitigation_forced,
        limit=limit_val,
        offset=0,
        sort=sort,
    )
    return items


def stream(
    *,
    start: Optional[Union[str, datetime]] = None,
    end: Optional[Union[str, datetime]] = None,
    tenant: Optional[str] = None,
    bot: Optional[str] = None,
    provider: Optional[str] = None,
    request_id: Optional[str] = None,
    rule_id: Optional[str] = None,
    decision: Optional[str] = None,
    mitigation_forced: Optional[str] = None,
    limit: Optional[int] = 100,
    sort: str = "ts_desc",
) -> Iterator[str]:
    if isinstance(start, datetime):
        start_dt: Optional[datetime] = start.astimezone(timezone.utc)
    else:
        start_dt = _parse_ts(start) if start else None
    if isinstance(end, datetime):
        end_dt: Optional[datetime] = end.astimezone(timezone.utc)
    else:
        end_dt = _parse_ts(end) if end else None

    if limit is None:
        limit_val: Optional[int] = None
    else:
        try:
            limit_val = max(int(limit), 0)
        except Exception:
            limit_val = 0

    count = 0
    for rec in _iter_filtered(
        start=start_dt,
        end=end_dt,
        tenant=tenant,
        bot=bot,
        provider=provider,
        request_id=request_id,
        rule_id=rule_id,
        decision=decision,
        mitigation_forced=mitigation_forced,
        sort=sort,
    ):
        if limit_val is not None and count >= limit_val:
            break
        try:
            yield json.dumps(rec.to_dict(), separators=(",", ":")) + "\n"
        except Exception:
            continue
        count += 1


__all__ = [
    "AdjudicationRecord",
    "append",
    "clear",
    "iter_records",
    "paged_query",
    "list_with_cursor",
    "query",
    "stream",
    "_now_ts",
]

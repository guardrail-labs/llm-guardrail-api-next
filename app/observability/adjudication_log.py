from __future__ import annotations

import json
import os
import threading
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Deque, Iterable, Iterator, List, Optional


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
    mitigation_forced: Optional[str] = None

    def to_dict(self) -> dict:
        data = asdict(self)
        return data


_CAP = _coerce_cap(os.getenv("ADJUDICATION_LOG_CAP"))
_BUFFER: Deque[AdjudicationRecord] = deque(maxlen=_CAP)
_LOCK = threading.Lock()


def _matches(
    record: AdjudicationRecord,
    *,
    start: Optional[datetime],
    end: Optional[datetime],
    tenant: Optional[str],
    bot: Optional[str],
    provider: Optional[str],
    request_id: Optional[str],
) -> bool:
    if tenant and record.tenant != tenant:
        return False
    if bot and record.bot != bot:
        return False
    if provider and record.provider != provider:
        return False
    if request_id and record.request_id != request_id:
        return False

    ts_dt = _parse_ts(record.ts)
    if start and ts_dt and ts_dt < start:
        return False
    if end and ts_dt and ts_dt > end:
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


def query(
    *,
    start: Optional[str] = None,
    end: Optional[str] = None,
    tenant: Optional[str] = None,
    bot: Optional[str] = None,
    provider: Optional[str] = None,
    request_id: Optional[str] = None,
    limit: int = 100,
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

    with _LOCK:
        items: Iterable[AdjudicationRecord] = list(_BUFFER)

    out: List[AdjudicationRecord] = []
    for rec in reversed(list(items)):
        if _matches(
            rec,
            start=start_dt,
            end=end_dt,
            tenant=tenant,
            bot=bot,
            provider=provider,
            request_id=request_id,
        ):
            out.append(rec)
            if len(out) >= limit_val:
                break
    return out


def stream(
    *,
    start: Optional[str] = None,
    end: Optional[str] = None,
    tenant: Optional[str] = None,
    bot: Optional[str] = None,
    provider: Optional[str] = None,
    request_id: Optional[str] = None,
    limit: int = 100,
) -> Iterator[str]:
    records = query(
        start=start,
        end=end,
        tenant=tenant,
        bot=bot,
        provider=provider,
        request_id=request_id,
        limit=limit,
    )
    for rec in records:
        try:
            yield json.dumps(rec.to_dict(), separators=(",", ":")) + "\n"
        except Exception:
            continue


__all__ = [
    "AdjudicationRecord",
    "append",
    "clear",
    "query",
    "stream",
    "_now_ts",
]

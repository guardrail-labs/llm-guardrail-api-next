from __future__ import annotations

import collections
import json
import os
import queue
import threading
import time
from typing import Any, Deque, Dict, Iterator, Optional

# Runtime-configurable storage
_PATH = os.getenv("DECISIONS_AUDIT_PATH", "var/decisions.jsonl")
_MAX = int(os.getenv("DECISIONS_BUFFER_MAX", "2000"))

_lock = threading.RLock()
_buf: Deque[Dict[str, Any]] = collections.deque(maxlen=_MAX)

# Subscribers receive events on a SimpleQueue published by publish().
_subscribers: set[queue.SimpleQueue[Dict[str, Any]]] = set()


def _ensure_dir(path: str) -> None:
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)


def publish(evt: Dict[str, Any]) -> None:
    """Publish a decision event to buffer, audit log, and subscriber queues."""
    with _lock:
        if "ts" not in evt:
            evt["ts"] = int(time.time())

        # ring buffer
        _buf.append(evt)

        # append-only audit log
        _ensure_dir(_PATH)
        with open(_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(evt) + "\n")

        # fan-out to subscribers (non-blocking)
        dead: list[queue.SimpleQueue[Dict[str, Any]]] = []
        for q in _subscribers:
            try:
                q.put_nowait(evt)
            except Exception:
                dead.append(q)
        for q in dead:
            _subscribers.discard(q)


def snapshot() -> list[Dict[str, Any]]:
    """Return a copy of the current buffer (newest last)."""
    with _lock:
        return list(_buf)


def iter_all() -> Iterator[Dict[str, Any]]:
    """Iterate over a snapshot of all buffered decisions."""

    with _lock:
        rows = list(_buf)

    for evt in rows:
        item = dict(evt)
        item.setdefault("ts_ms", _event_ts_ms(evt))
        yield item


def subscribe() -> queue.SimpleQueue[Dict[str, Any]]:
    """Create a subscriber queue that receives future events."""
    q: queue.SimpleQueue[Dict[str, Any]] = queue.SimpleQueue()
    with _lock:
        _subscribers.add(q)
    return q


def unsubscribe(q: queue.SimpleQueue[Dict[str, Any]]) -> None:
    """Remove a subscriber queue created by subscribe()."""
    with _lock:
        _subscribers.discard(q)


def configure(
    *,
    path: Optional[str] = None,
    max_size: Optional[int] = None,
    reset: bool = False,
) -> None:
    """Adjust runtime configuration (primarily for tests)."""
    global _PATH, _buf
    with _lock:
        if path is not None:
            _PATH = path

        if max_size is not None and max_size > 0:
            # Resize buffer while preserving most-recent entries
            new_len = int(max_size)
            new_buf: Deque[Dict[str, Any]] = collections.deque(_buf, maxlen=new_len)
            _buf = new_buf

        if reset:
            _buf.clear()


def _norm_str(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _event_decision(evt: Dict[str, Any]) -> Optional[str]:
    for key in ("decision", "family", "mode", "outcome"):
        raw = evt.get(key)
        if isinstance(raw, str):
            normalized = raw.strip().lower()
            if normalized:
                return normalized
    return None


def _event_rule_ids(evt: Dict[str, Any]) -> set[str]:
    values: set[str] = set()
    raw_single = evt.get("rule_id")
    if isinstance(raw_single, str) and raw_single.strip():
        values.add(raw_single.strip())
    raw_ids = evt.get("rule_ids")
    if isinstance(raw_ids, (list, tuple, set)):
        for item in raw_ids:
            if isinstance(item, str) and item.strip():
                values.add(item.strip())
            elif item is not None:
                values.add(str(item))
    elif isinstance(raw_ids, str) and raw_ids.strip():
        # Defensive: if stored as comma-separated string
        values.add(raw_ids.strip())
    return values


def _event_ts(evt: Dict[str, Any]) -> float:
    try:
        return float(evt.get("ts", 0))
    except Exception:
        return 0.0


def _event_ts_ms(evt: Dict[str, Any]) -> int:
    raw_ms = evt.get("ts_ms")
    if raw_ms is not None:
        try:
            return int(float(raw_ms))
        except Exception:
            pass
    raw = evt.get("ts")
    if isinstance(raw, (int, float)):
        value = float(raw)
        if value > 1_000_000_000_000:  # already ms
            return int(value)
        return int(value * 1000)
    if isinstance(raw, str):
        try:
            if raw.isdigit():
                value = float(raw)
                if value > 1_000_000_000_000:
                    return int(value)
                return int(value * 1000)
        except Exception:
            pass
    return int(_event_ts(evt) * 1000)


def iter_decisions(
    *,
    tenant: Optional[str] = None,
    bot: Optional[str] = None,
    rule_id: Optional[str] = None,
    request_id: Optional[str] = None,
    decision: Optional[str] = None,
    from_ts: Optional[int] = None,
    to_ts: Optional[int] = None,
    sort: str = "ts_desc",
) -> Iterator[Dict[str, Any]]:
    """Iterate over decisions that match the provided filters."""

    tenant_norm = _norm_str(tenant)
    bot_norm = _norm_str(bot)
    rule_id_norm = _norm_str(rule_id)
    decision_norm = _norm_str(decision)
    request_id_norm = _norm_str(request_id)
    with _lock:
        rows = list(_buf)

    filtered: list[Dict[str, Any]] = []
    for evt in rows:
        if tenant_norm and _norm_str(evt.get("tenant")) != tenant_norm:
            continue
        if bot_norm and _norm_str(evt.get("bot")) != bot_norm:
            continue
        if request_id_norm and _norm_str(evt.get("request_id")) != request_id_norm:
            continue
        if decision_norm:
            evt_decision = _event_decision(evt)
            if evt_decision != decision_norm:
                continue

        ts_value = _event_ts(evt)
        if from_ts is not None and ts_value < from_ts:
            continue
        if to_ts is not None and ts_value >= to_ts:
            continue

        if rule_id_norm and rule_id_norm not in _event_rule_ids(evt):
            continue

        filtered.append(evt)

    if sort == "ts_asc":
        filtered.sort(key=_event_ts)
    else:
        filtered.sort(key=_event_ts, reverse=True)

    for evt in filtered:
        yield evt


def list_decisions(
    *,
    tenant: Optional[str] = None,
    bot: Optional[str] = None,
    rule_id: Optional[str] = None,
    request_id: Optional[str] = None,
    decision: Optional[str] = None,
    from_ts: Optional[int] = None,
    to_ts: Optional[int] = None,
    sort: str = "ts_desc",
) -> list[Dict[str, Any]]:
    """Return a materialized list of decisions matching the filters."""

    return list(
        iter_decisions(
            tenant=tenant,
            bot=bot,
            rule_id=rule_id,
            request_id=request_id,
            decision=decision,
            from_ts=from_ts,
            to_ts=to_ts,
            sort=sort,
        )
    )


def delete_where(
    *,
    tenant: Optional[str],
    bot: Optional[str],
    before_ts_ms: Optional[int],
) -> int:
    """Delete matching decisions from the in-memory buffer."""

    tenant_norm = _norm_str(tenant)
    bot_norm = _norm_str(bot)
    cutoff = int(before_ts_ms) if before_ts_ms is not None else None
    removed = 0
    with _lock:
        keep: list[Dict[str, Any]] = []
        for evt in list(_buf):
            if tenant_norm and _norm_str(evt.get("tenant")) != tenant_norm:
                keep.append(evt)
                continue
            if bot_norm and _norm_str(evt.get("bot")) != bot_norm:
                keep.append(evt)
                continue
            ts_ms = _event_ts_ms(evt)
            if cutoff is not None and ts_ms >= cutoff:
                keep.append(evt)
                continue
            removed += 1
        if removed:
            _buf.clear()
            for evt in keep:
                _buf.append(evt)
    return removed


__all__ = [
    "configure",
    "delete_where",
    "iter_all",
    "iter_decisions",
    "list_decisions",
    "publish",
    "snapshot",
    "subscribe",
    "unsubscribe",
]

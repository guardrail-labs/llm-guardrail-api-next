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


def _event_ts(evt: Dict[str, Any]) -> int:
    raw = evt.get("ts")
    if isinstance(raw, (int, float)):
        return int(raw)
    if isinstance(raw, str):
        try:
            return int(raw.strip())
        except Exception:
            return 0
    return 0


def iter_decisions(
    *,
    tenant: Optional[str] = None,
    bot: Optional[str] = None,
    rule_id: Optional[str] = None,
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
    with _lock:
        rows = list(_buf)

    if sort == "ts_asc":
        iterable = rows
    else:
        iterable = list(reversed(rows))

    for evt in iterable:
        if tenant_norm and _norm_str(evt.get("tenant")) != tenant_norm:
            continue
        if bot_norm and _norm_str(evt.get("bot")) != bot_norm:
            continue
        if decision_norm:
            evt_decision = _event_decision(evt)
            if evt_decision != decision_norm:
                continue
        if from_ts is not None:
            if _event_ts(evt) < from_ts:
                continue
        if to_ts is not None:
            if _event_ts(evt) >= to_ts:
                continue
        if rule_id_norm:
            if rule_id_norm not in _event_rule_ids(evt):
                continue
        yield evt


def list_decisions(
    *,
    tenant: Optional[str] = None,
    bot: Optional[str] = None,
    rule_id: Optional[str] = None,
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
            decision=decision,
            from_ts=from_ts,
            to_ts=to_ts,
            sort=sort,
        )
    )

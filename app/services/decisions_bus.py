from __future__ import annotations

import collections
import json
import os
import queue
import threading
import time
from typing import Any, Deque, Dict, Iterable, Optional

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
    """Publish a decision event to the in-memory buffer, audit log, and subscribers."""
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
                # extremely rare; mark dead and drop after iteration
                dead.append(q)
        for q in dead:
            _subscribers.discard(q)


def snapshot() -> list[Dict[str, Any]]:
    """Return a copy of the current buffer (newest last)."""
    with _lock:
        return list(_buf)


def subscribe() -> queue.SimpleQueue[Dict[str, Any]]:
    """
    Create a subscriber queue that receives future events.
    Caller must call unsubscribe(q) when done.
    """
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

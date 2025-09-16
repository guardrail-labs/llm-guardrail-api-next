from __future__ import annotations

import collections
import json
import os
import threading
import time
from typing import Any, Deque, Dict, Iterator, Optional, Tuple

# Runtime-configurable storage
_PATH = os.getenv("DECISIONS_AUDIT_PATH", "var/decisions.jsonl")
_MAX = int(os.getenv("DECISIONS_BUFFER_MAX", "2000"))

_lock = threading.RLock()
_buf: Deque[Dict[str, Any]] = collections.deque(maxlen=_MAX)

# Subscribers are simple generators that receive events via .send(evt)
# We keep (gen,) so we can drop dead ones on StopIteration.
_listeners: set[Tuple[Iterator[Dict[str, Any]],]] = set()


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

        # fan-out to subscribers
        dead: list[Tuple[Iterator[Dict[str, Any]],]] = []
        for (gen,) in _listeners:
            try:
                gen.send(evt)
            except StopIteration:
                dead.append((gen,))
        for item in dead:
            _listeners.discard(item)


def snapshot() -> list[Dict[str, Any]]:
    """Return a copy of the current buffer (newest last)."""
    with _lock:
        return list(_buf)


def subscribe() -> Iterator[Dict[str, Any]]:
    """
    Return a primed generator that accepts events via .send(evt).

    NOTE: This iterator yields nothing by itself; callers typically call
    .send(None) to step the generator, and we push events via publish().
    """
    def _gen() -> Iterator[Dict[str, Any]]:
        try:
            while True:
                # Wait to receive an event from publish() via .send(evt)
                evt = (yield)  # type: ignore[misc]
                # No-op: we don't yield back here; the caller controls streaming.
                # (SSE handlers usually keep their own snapshot and formatting.)
                _ = evt
        finally:
            # generator closed by caller
            return

    it = _gen()
    next(it)  # prime
    with _lock:
        _listeners.add((it,))
    return it


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

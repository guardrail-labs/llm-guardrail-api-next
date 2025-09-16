from __future__ import annotations

import collections
import copy
import json
import os
import threading
import time
from typing import Any, Deque, Dict, Iterable, Iterator, Optional, Set

__all__ = ["publish", "snapshot", "subscribe", "unsubscribe", "configure"]


class DecisionsSubscription(Iterator[Dict[str, Any]]):
    """Thread-safe subscription queue for live decision events."""

    def __init__(self) -> None:
        self._queue: Deque[Dict[str, Any]] = collections.deque()
        self._cond = threading.Condition()
        self._closed = False

    def push(self, evt: Dict[str, Any]) -> bool:
        with self._cond:
            if self._closed:
                return False
            self._queue.append(evt)
            self._cond.notify()
            return True

    def get(self, timeout: Optional[float] = None) -> Dict[str, Any]:
        with self._cond:
            if timeout is None:
                while not self._queue:
                    if self._closed:
                        raise StopIteration
                    self._cond.wait()
            else:
                end = time.time() + timeout
                while not self._queue and not self._closed:
                    remaining = end - time.time()
                    if remaining <= 0:
                        break
                    self._cond.wait(remaining)
            if self._queue:
                return self._queue.popleft()
            raise StopIteration

    def close(self) -> None:
        with self._cond:
            self._closed = True
            self._cond.notify_all()

    # Iterator API -----------------------------------------------------
    def __iter__(self) -> "DecisionsSubscription":
        return self

    def __next__(self) -> Dict[str, Any]:
        return self.get()


_lock = threading.RLock()
_max = int(os.getenv("DECISIONS_BUFFER_MAX", "2000"))
_path = os.getenv("DECISIONS_AUDIT_PATH", "var/decisions.jsonl")
_buf: Deque[Dict[str, Any]] = collections.deque(maxlen=_max)
_listeners: Set[DecisionsSubscription] = set()


def _ensure_dir() -> None:
    directory = os.path.dirname(_path) or "."
    os.makedirs(directory, exist_ok=True)


def configure(*, path: Optional[str] = None, max_size: Optional[int] = None, reset: bool = False) -> None:
    """Adjust runtime configuration (primarily for tests)."""

    global _path, _buf, _max
    with _lock:
        if path is not None:
            _path = path
        if max_size is not None and max_size > 0:
            items = list(_buf)
            _max = max_size
            _buf = collections.deque(items[-max_size:], maxlen=max_size)
        if reset:
            _buf.clear()
            if path:
                try:
                    os.remove(path)
                except FileNotFoundError:
                    pass


def publish(evt: Dict[str, Any]) -> None:
    data = dict(evt)
    data.setdefault("ts", int(time.time()))

    with _lock:
        _buf.append(copy.deepcopy(data))
        try:
            _ensure_dir()
            with open(_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(data, ensure_ascii=False) + "\n")
        except Exception:
            # Persistence failures shouldn't break request handling.
            pass

        stale: Set[DecisionsSubscription] = set()
        for listener in list(_listeners):
            if not listener.push(copy.deepcopy(data)):
                stale.add(listener)
        for listener in stale:
            _listeners.discard(listener)


def snapshot() -> Iterable[Dict[str, Any]]:
    with _lock:
        return [copy.deepcopy(evt) for evt in _buf]


def subscribe() -> DecisionsSubscription:
    listener = DecisionsSubscription()
    with _lock:
        _listeners.add(listener)
    return listener


def unsubscribe(listener: DecisionsSubscription) -> None:
    with _lock:
        if listener in _listeners:
            _listeners.remove(listener)
    listener.close()

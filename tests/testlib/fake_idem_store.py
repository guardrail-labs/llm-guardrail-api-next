from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

from app.idempotency.store import StoredResponse


@dataclass
class _Entry:
    owner: Optional[str] = None
    value: Optional[StoredResponse] = None
    payload_fingerprint: Optional[str] = None
    state: str = "idle"  # idle | in_progress
    lock_expires_at: float = 0.0
    ttl_expires_at: float = 0.0


class RecordingStore:
    """
    Minimal in-memory IdemStore for tests.

    - Leader acquisition with owner token.
    - TTL expiry for stored responses.
    - Lock TTL and meta state for followers to poll.
    """

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._data: Dict[str, _Entry] = {}
        self.touch_calls: Dict[str, int] = {}
        self.acquire_calls: Dict[str, int] = {}

    async def acquire_leader(
        self, key: str, ttl_s: int, body_fp: str
    ) -> Tuple[bool, Optional[str]]:
        async with self._lock:
            e = self._data.setdefault(key, _Entry())
            now = time.time()
            if e.owner and e.lock_expires_at > now:
                self.acquire_calls[key] = self.acquire_calls.get(key, 0) + 1
                return False, e.owner
            # grant leadership
            e.owner = f"owner-{key}-{int(now * 1000)}"
            e.state = "in_progress"
            e.payload_fingerprint = body_fp
            e.lock_expires_at = now + float(ttl_s)
            self.acquire_calls[key] = self.acquire_calls.get(key, 0) + 1
            return True, e.owner

    async def release(self, key: str, owner: Optional[str] = None) -> None:
        async with self._lock:
            e = self._data.setdefault(key, _Entry())
            if owner and e.owner != owner:
                return
            e.owner = None
            e.state = "idle"
            e.lock_expires_at = 0.0

    async def get(self, key: str) -> Optional[StoredResponse]:
        async with self._lock:
            e = self._data.get(key)
            if not e or not e.value:
                return None
            if e.ttl_expires_at and e.ttl_expires_at < time.time():
                e.value = None
                return None
            return e.value

    async def put(self, key: str, value: StoredResponse, ttl_s: int) -> None:
        async with self._lock:
            e = self._data.setdefault(key, _Entry())
            e.value = value
            e.ttl_expires_at = time.time() + float(ttl_s)
            e.state = "idle"

    async def meta(self, key: str) -> Mapping[str, Any]:
        async with self._lock:
            e = self._data.setdefault(key, _Entry())
            return {
                "state": e.state,
                "payload_fingerprint": e.payload_fingerprint,
                "lock": bool(e.owner),
                "lock_expires_at": e.lock_expires_at,
            }

    async def bump_replay(self, key: str) -> Optional[int]:
        async with self._lock:
            e = self._data.setdefault(key, _Entry())
            if not e.value:
                return None
            current = (e.value.replay_count or 0) + 1
            e.value.replay_count = current
            return current

    async def touch(self, key: str, ttl_s: int) -> None:
        async with self._lock:
            e = self._data.setdefault(key, _Entry())
            if e.value:
                e.ttl_expires_at = time.time() + float(ttl_s)
            self.touch_calls[key] = self.touch_calls.get(key, 0) + 1

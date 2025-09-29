"""Simple in-memory idempotency store for tests and local development."""

from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import Any, Deque, Dict, List, Mapping, Optional, Tuple

from app.idempotency.store import IdemStore, StoredResponse


class InMemoryIdemStore(IdemStore):
    def __init__(self, recent_limit: Optional[int] = None) -> None:
        self._lock = asyncio.Lock()
        self._values: Dict[str, Tuple[StoredResponse, float]] = {}
        self._locks: Dict[str, Tuple[str, float]] = {}
        self._states: Dict[str, Tuple[str, float]] = {}
        self._recent: Deque[Tuple[str, float]] = deque()
        self._recent_limit = recent_limit

    async def acquire_leader(
        self, key: str, ttl_s: int, payload_fingerprint: str
    ) -> bool:
        async with self._lock:
            now = time.time()
            self._expire_locked(now)
            lock = self._locks.get(key)
            if lock and lock[1] > now:
                return False
            expires = now + ttl_s
            self._locks[key] = (payload_fingerprint, expires)
            self._states[key] = ("in_progress", expires)
            self._append_recent(key, now)
            return True

    async def get(self, key: str) -> Optional[StoredResponse]:
        async with self._lock:
            now = time.time()
            self._expire_locked(now)
            value = self._values.get(key)
            if not value:
                return None
            stored, expires = value
            if expires <= now:
                self._values.pop(key, None)
                self._states.pop(key, None)
                return None
            return stored

    async def put(self, key: str, resp: StoredResponse, ttl_s: int) -> None:
        async with self._lock:
            now = time.time()
            expires = now + ttl_s
            self._values[key] = (resp, expires)
            self._states[key] = ("stored", expires)
            self._locks.pop(key, None)
            self._append_recent(key, now)

    async def release(self, key: str) -> None:
        async with self._lock:
            self._locks.pop(key, None)
            self._states.pop(key, None)

    async def meta(self, key: str) -> Mapping[str, Any]:
        async with self._lock:
            now = time.time()
            self._expire_locked(now)
            state = self._states.get(key)
            lock = self._locks.get(key)
            state_text = state[0] if state and state[1] > now else None
            lock_valid = lock and lock[1] > now
            payload_fp = lock[0] if lock_valid else None
            return {
                "state": state_text,
                "lock": bool(lock_valid),
                "payload_fingerprint": payload_fp,
            }

    async def purge(self, key: str) -> bool:
        async with self._lock:
            existed = bool(
                self._values.pop(key, None)
                or self._locks.pop(key, None)
                or self._states.pop(key, None)
            )
            return existed

    async def list_recent(self, limit: int = 50) -> List[Tuple[str, float]]:
        async with self._lock:
            results: List[Tuple[str, float]] = []
            seen = set()
            for key, ts in reversed(self._recent):
                if key in seen:
                    continue
                seen.add(key)
                results.append((key, ts))
                if len(results) >= limit:
                    break
            return results

    def _append_recent(self, key: str, ts: float) -> None:
        self._recent.append((key, ts))
        if self._recent_limit and self._recent_limit > 0:
            while len(self._recent) > self._recent_limit:
                self._recent.popleft()

    def _expire_locked(self, now: float) -> None:
        expired_keys = [k for k, (_, exp) in self._locks.items() if exp <= now]
        for k in expired_keys:
            self._locks.pop(k, None)
        expired_values = [k for k, (_, exp) in self._values.items() if exp <= now]
        for k in expired_values:
            self._values.pop(k, None)
        expired_states = [k for k, (_, exp) in self._states.items() if exp <= now]
        for k in expired_states:
            self._states.pop(k, None)

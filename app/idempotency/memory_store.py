"""In-memory idempotency store (test/dev) compatible with IdemStore Protocol."""

from __future__ import annotations

import asyncio
import base64
import json
import time
from typing import Any, Dict, List, Mapping, Optional, Tuple

from app.idempotency.store import IdemStore, StoredResponse

__all__ = ["MemoryIdemStore"]


def _now() -> float:
    return time.time()


class MemoryIdemStore(IdemStore):
    """
    Simple in-memory store for idempotency, intended for tests and local dev.

    Data model (all guarded by a single asyncio.Lock for simplicity):
      - _locks: key -> (payload_fingerprint, expires_at)
      - _states: key -> (state_text, expires_at)  # "in_progress" | "stored"
      - _values: key -> (StoredResponse, expires_at)
      - _recent: list[(key, timestamp)]           # unbounded; trimmed by recent_limit if set
    """

    def __init__(self, *, recent_limit: Optional[int] = 5000) -> None:
        self._locks: Dict[str, Tuple[str, float]] = {}
        self._states: Dict[str, Tuple[str, float]] = {}
        self._values: Dict[str, Tuple[StoredResponse, float]] = {}
        self._recent: List[Tuple[str, float]] = []
        self._recent_limit = recent_limit
        self._mu = asyncio.Lock()

    # ---- internal helpers -------------------------------------------------

    def _prune(self) -> None:
        """Remove expired locks/states/values."""
        now = _now()
        # Locks
        expired = [k for k, (_, exp) in self._locks.items() if exp <= now]
        for k in expired:
            self._locks.pop(k, None)
        # States
        expired = [k for k, (_, exp) in self._states.items() if exp <= now]
        for k in expired:
            self._states.pop(k, None)
        # Values
        expired = [k for k, (_, exp) in self._values.items() if exp <= now]
        for k in expired:
            self._values.pop(k, None)

    def _touch_recent(self, key: str) -> None:
        ts = _now()
        self._recent.append((key, ts))
        if self._recent_limit and self._recent_limit > 0:
            # Trim oldest; keep only the newest N entries
            overflow = len(self._recent) - self._recent_limit
            if overflow > 0:
                del self._recent[0:overflow]

    # ---- protocol methods -------------------------------------------------

    async def acquire_leader(
        self, key: str, ttl_s: int, payload_fingerprint: str
    ) -> bool:
        async with self._mu:
            self._prune()
            now = _now()
            lock = self._locks.get(key)
            if lock is not None:
                # Lock exists; if not expired, deny acquisition.
                _, exp = lock
                if exp > now:
                    return False
            # Acquire
            expires_at = now + float(ttl_s)
            self._locks[key] = (payload_fingerprint, expires_at)
            self._states[key] = ("in_progress", expires_at)
            self._touch_recent(key)
            return True

    async def get(self, key: str) -> Optional[StoredResponse]:
        async with self._mu:
            self._prune()
            pair = self._values.get(key)
            if pair is None:
                return None
            value, exp = pair
            if exp <= _now():
                # Expired; remove and return None.
                self._values.pop(key, None)
                self._states.pop(key, None)
                return None
            return value

    async def put(self, key: str, resp: StoredResponse, ttl_s: int) -> None:
        async with self._mu:
            self._prune()
            exp = _now() + float(ttl_s)
            # Normalize headers to lower-case for replay consistency.
            norm_headers = {k.lower(): v for k, v in resp.headers.items()}
            stored = StoredResponse(
                status=resp.status,
                headers=norm_headers,
                body=bytes(resp.body),
                content_type=resp.content_type,
                stored_at=resp.stored_at or _now(),
                replay_count=resp.replay_count,
                body_sha256=resp.body_sha256,
            )
            self._values[key] = (stored, exp)
            self._states[key] = ("stored", exp)
            # Clear lock on success (mirrors Redis implementation).
            self._locks.pop(key, None)

    async def release(self, key: str) -> None:
        async with self._mu:
            self._locks.pop(key, None)

    async def meta(self, key: str) -> Mapping[str, Any]:
        async with self._mu:
            self._prune()
            state_pair = self._states.get(key)
            state_text: Optional[str]
            if state_pair is None:
                state_text = None
            else:
                state_text, _ = state_pair

            lock = self._locks.get(key)
            if lock is not None:
                payload_fp, _ = lock
                lock_present = True
            else:
                payload_fp = None
                lock_present = False

            return {
                "state": state_text,
                "lock": lock_present,
                "payload_fingerprint": payload_fp,
            }

    async def purge(self, key: str) -> bool:
        async with self._mu:
            existed = False
            if key in self._values:
                existed = True
                self._values.pop(key, None)
            if key in self._states:
                existed = True
                self._states.pop(key, None)
            if key in self._locks:
                existed = True
                self._locks.pop(key, None)
            return existed

    async def list_recent(self, limit: int = 50) -> List[Tuple[str, float]]:
        async with self._mu:
            if limit <= 0:
                return []
            # Return newest-first
            return list(self._recent[-limit:])[::-1]

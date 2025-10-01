"""In-memory idempotency store (test/dev), now with owner tokens."""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Mapping, Optional, Tuple

from app.idempotency.store import IdemStore, StoredResponse


class MemoryIdemStore(IdemStore):
    """
    Non-persistent store for tests & local dev.

    Data structures:
      - _values: key -> StoredResponse
      - _state: key -> "in_progress" | "stored"
      - _locks: key -> (owner_token, expires_at, payload_fingerprint)
      - _recent: list[(key, timestamp)] (append-only; truncated)
    """

    def __init__(self, recent_limit: Optional[int] = 100) -> None:
        self._values: Dict[str, StoredResponse] = {}
        self._state: Dict[str, str] = {}
        self._locks: Dict[str, Tuple[str, float, str]] = {}
        self._recent: List[Tuple[str, float]] = []
        self._recent_limit = recent_limit or 0

    def _prune_lock_if_expired(self, key: str) -> None:
        lock = self._locks.get(key)
        if not lock:
            return
        owner, exp, _fp = lock
        if exp <= time.time():
            # Expired lock; clear it and state if still in_progress.
            self._locks.pop(key, None)
            if self._state.get(key) == "in_progress":
                self._state.pop(key, None)

    async def acquire_leader(
        self, key: str, ttl_s: int, payload_fingerprint: str
    ) -> Tuple[bool, Optional[str]]:
        self._prune_lock_if_expired(key)
        if key in self._locks:
            return False, None
        owner = str(uuid.uuid4())
        self._locks[key] = (owner, time.time() + float(ttl_s), payload_fingerprint)
        self._state[key] = "in_progress"
        now = time.time()
        self._recent.append((key, now))
        if self._recent_limit > 0 and len(self._recent) > self._recent_limit:
            # keep newest N
            self._recent = self._recent[-self._recent_limit :]
        return True, owner

    async def get(self, key: str) -> Optional[StoredResponse]:
        return self._values.get(key)

    async def put(self, key: str, resp: StoredResponse, ttl_s: int) -> None:  # noqa: ARG002
        # TTL is ignored in memory store (kept simple for tests)
        self._values[key] = resp
        self._state[key] = "stored"
        # Do not implicitly clear lock; the leader should call release(owner=...)
        # but for safety, if an old lock exists we clear it.
        self._locks.pop(key, None)

    async def release(self, key: str, owner: Optional[str] = None) -> bool:
        self._prune_lock_if_expired(key)
        lock = self._locks.get(key)
        if not lock:
            return False
        lock_owner, _exp, _fp = lock
        if owner is not None and owner != lock_owner:
            # Wrong owner -> do not release
            return False
        self._locks.pop(key, None)
        # If we were still in progress, allow followers to proceed.
        if self._state.get(key) == "in_progress":
            self._state.pop(key, None)
        return True

    async def meta(self, key: str) -> Mapping[str, Any]:
        self._prune_lock_if_expired(key)
        lock = self._locks.get(key)
        state = self._state.get(key)
        val = self._values.get(key)
        ttl_remaining: Optional[float] = None
        payload_fp: Optional[str] = None
        owner: Optional[str] = None
        if lock:
            owner, exp, payload_fp = lock
            ttl_remaining = max(exp - time.time(), 0.0)

        return {
            "state": state,
            "lock": bool(lock),
            "owner": owner,
            "payload_fingerprint": payload_fp,
            "stored_at": val.stored_at if val else None,
            "replay_count": val.replay_count if val else None,
            "ttl_remaining": ttl_remaining,
        }

    async def purge(self, key: str) -> bool:
        removed = False
        removed |= self._values.pop(key, None) is not None
        removed |= self._state.pop(key, None) is not None
        removed |= self._locks.pop(key, None) is not None
        return bool(removed)

    async def list_recent(self, limit: int = 50) -> List[Tuple[str, float]]:
        if limit <= 0:
            return []
        # newest first
        return list(reversed(self._recent[-limit:]))


# Back-compat alias used by runtime/tests
InMemoryIdemStore = MemoryIdemStore

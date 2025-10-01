"""In-memory idempotency store (test/dev) with ownership & replay bump."""
from __future__ import annotations

import asyncio
import secrets
import time
from typing import Any, Dict, List, Mapping, Optional, Tuple

from app.idempotency.store import IdemStore, StoredResponse

_RELEASE_STATE_TTL = 60  # seconds, for post-release 'released' marker


class MemoryIdemStore(IdemStore):
    """Simple in-memory store; NOT suitable for multi-process or multi-worker."""

    def __init__(
        self,
        ns: str = "idem",
        tenant: str = "default",
        recent_limit: Optional[int] = 100,
    ) -> None:
        self.ns = ns
        self.tenant = tenant
        self.recent_limit = recent_limit

        # Keyed by idem key
        # Values are (StoredResponse, expiry_epoch_seconds)
        self._values: Dict[str, Tuple[StoredResponse, float]] = {}
        # States are (state_string, expiry_epoch_seconds)
        self._states: Dict[str, Tuple[str, float]] = {}
        # lock info: {"owner": str, "payload_fingerprint": str, "expiry": float}
        self._locks: Dict[str, Dict[str, Any]] = {}
        # recent entries as an ordered list of (key, timestamp)
        self._recent: List[Tuple[str, float]] = []
        # first time each key was seen (persisted while process alive)
        self._first_seen: Dict[str, float] = {}

        # Hide lock from type checker; tests use "type: ignore[attr-defined]".
        self.__dict__["_mu"] = asyncio.Lock()

    def _now(self) -> float:
        return time.time()

    def _recent_append(self, key: str) -> None:
        """Append (key, now) and cap by recent_limit if set."""
        now = self._now()
        self._recent.append((key, now))
        self._first_seen.setdefault(key, now)
        if self.recent_limit and self.recent_limit > 0:
            # keep only the last N entries
            over = len(self._recent) - self.recent_limit
            if over > 0:
                del self._recent[0:over]

    async def acquire_leader(
        self,
        key: str,
        ttl_s: int,
        payload_fingerprint: str,
    ) -> Tuple[bool, Optional[str]]:
        async with self.__dict__["_mu"]:
            info = self._locks.get(key)
            if info and info.get("expiry", 0.0) > self._now():
                return False, None
            owner = secrets.token_urlsafe(16)
            exp = self._now() + float(ttl_s)
            self._locks[key] = {
                "owner": owner,
                "payload_fingerprint": payload_fingerprint,
                "expiry": exp,
            }
            self._states[key] = ("in_progress", exp)
            self._recent_append(key)
            return True, owner

    async def get(self, key: str) -> Optional[StoredResponse]:
        async with self.__dict__["_mu"]:
            tup = self._values.get(key)
            return tup[0] if tup else None

    async def put(self, key: str, resp: StoredResponse, ttl_s: int) -> None:  # noqa: ARG002
        async with self.__dict__["_mu"]:
            exp = self._now() + float(ttl_s)
            self._values[key] = (resp, exp)
            self._states[key] = ("stored", exp)
            self._locks.pop(key, None)
            self._recent_append(key)

    async def release(self, key: str, owner: Optional[str] = None) -> bool:
        async with self.__dict__["_mu"]:
            info = self._locks.get(key)
            if not info:
                return False
            if owner and info.get("owner") != owner:
                return False
            self._locks.pop(key, None)
            self._states[key] = ("released", self._now() + _RELEASE_STATE_TTL)
            return True

    async def meta(self, key: str) -> Mapping[str, Any]:
        async with self.__dict__["_mu"]:
            info = self._locks.get(key)
            state_tuple = self._states.get(key)
            return {
                "state": state_tuple[0] if state_tuple else None,
                "lock": bool(info),
                "payload_fingerprint": info.get("payload_fingerprint") if info else None,
            }

    async def purge(self, key: str) -> bool:
        async with self.__dict__["_mu"]:
            before = any((key in self._values, key in self._states, key in self._locks))
            self._values.pop(key, None)
            self._states.pop(key, None)
            self._locks.pop(key, None)
            # keep _recent as historical trail; not purged
            return before

    async def list_recent(self, limit: int = 50) -> List[Tuple[str, float]]:
        async with self.__dict__["_mu"]:
            # Return last N entries (most recent at end)
            if limit <= 0:
                return []
            return self._recent[-limit:].copy()

    async def inspect(self, key: str) -> Mapping[str, Any]:
        async with self.__dict__["_mu"]:
            value_entry = self._values.get(key)
            state_entry = self._states.get(key)
            lock_entry = self._locks.get(key)

            state = state_entry[0] if state_entry else None
            expires_at = 0.0
            if state_entry:
                expires_at = max(expires_at, float(state_entry[1] or 0.0))
            if lock_entry:
                expires_at = max(expires_at, float(lock_entry.get("expiry") or 0.0))
                state = state or "in_progress"
            if value_entry:
                expires_at = max(expires_at, float(value_entry[1] or 0.0))

            resp = value_entry[0] if value_entry else None
            payload_prefix: Optional[str] = None
            if resp and resp.body_sha256:
                payload_prefix = resp.body_sha256[:8]
            elif lock_entry:
                fp = lock_entry.get("payload_fingerprint")
                if fp:
                    payload_prefix = str(fp)[:8]

            size_bytes = len(resp.body) if resp else 0
            stored_at = float(resp.stored_at or 0.0) if resp else 0.0
            replay_count: Optional[int] = None
            if resp and resp.replay_count is not None:
                replay_count = int(resp.replay_count)

            last_seen: Optional[float] = None
            for recent_key, ts in reversed(self._recent):
                if recent_key == key:
                    last_seen = ts
                    break

            first_seen = self._first_seen.get(key)

            return {
                "state": state or "missing",
                "expires_at": float(expires_at or 0.0),
                "replay_count": replay_count,
                "stored_at": stored_at,
                "size_bytes": size_bytes,
                "content_type": resp.content_type if resp else None,
                "payload_fingerprint_prefix": payload_prefix,
                "first_seen_at": float(first_seen) if first_seen else None,
                "last_seen_at": float(last_seen) if last_seen else None,
            }

    async def bump_replay(
        self,
        key: str,
        *,
        touch_ttl_s: Optional[int] = None,
    ) -> Optional[int]:
        async with self.__dict__["_mu"]:
            tup = self._values.get(key)
            if not tup:
                return None
            resp, value_expiry = tup
            new_count = int((resp.replay_count or 0) + 1)
            new_resp = StoredResponse(
                status=resp.status,
                headers=resp.headers,
                body=resp.body,
                content_type=resp.content_type,
                stored_at=resp.stored_at,
                replay_count=new_count,
                body_sha256=resp.body_sha256,
            )

            # If touching, refresh both value & state expiries and recent trail.
            if touch_ttl_s is not None:
                new_expiry = self._now() + float(touch_ttl_s)
                self._values[key] = (new_resp, new_expiry)
                state, _ = self._states.get(key, ("stored", new_expiry))
                self._states[key] = (state, new_expiry)
                self._recent_append(key)
            else:
                self._values[key] = (new_resp, value_expiry)

            return new_count


# Backwards-compat name expected by some imports/tests
InMemoryIdemStore = MemoryIdemStore

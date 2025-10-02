"""In-memory idempotency store (test/dev) with ownership & replay bump."""
from __future__ import annotations

import asyncio
import secrets
import time
from typing import Any, Dict, List, Mapping, Optional, Tuple

from app.idempotency.store import IdemStore, StoredResponse
from app.metrics import IDEMP_TOUCHES

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
            # do not update recent here; acquire already added it

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
            if limit <= 0:
                return []
            # newest entries should be returned first for admin display
            return list(reversed(self._recent[-limit:]))

    async def inspect(self, key: str) -> Mapping[str, Any]:
        async with self.__dict__["_mu"]:
            now = self._now()
            state_tuple = self._states.get(key)
            lock_info = self._locks.get(key)
            value_tuple = self._values.get(key)

            state = state_tuple[0] if state_tuple else None
            expires_candidates: List[float] = []
            if state_tuple:
                expires_candidates.append(state_tuple[1])
            if lock_info:
                expires_candidates.append(float(lock_info.get("expiry", 0.0)))
            if value_tuple:
                expires_candidates.append(value_tuple[1])
            expires_at = max(expires_candidates) if expires_candidates else 0.0

            replay_count = 0
            stored_at = 0.0
            size_bytes = 0
            content_type: Optional[str] = None
            fp_prefix: Optional[str] = None

            if value_tuple and (not expires_at or expires_at > now):
                resp, _ = value_tuple
                replay_count = int(resp.replay_count or 0)
                stored_at = float(resp.stored_at or 0.0)
                size_bytes = len(resp.body)
                content_type = resp.content_type
                if resp.body_sha256:
                    fp_prefix = resp.body_sha256[:8]
            elif lock_info and lock_info.get("payload_fingerprint"):
                fp_prefix = str(lock_info["payload_fingerprint"])[:8]

            if not state:
                state = "missing"

            first_seen = self._first_seen.get(key, 0.0)
            if not state or state == "missing":
                first_seen = 0.0

            return {
                "state": state,
                "expires_at": expires_at if expires_at > 0 else 0.0,
                "replay_count": replay_count,
                "stored_at": stored_at,
                "size_bytes": size_bytes,
                "content_type": content_type,
                "payload_fingerprint_prefix": fp_prefix,
                "first_seen_at": first_seen,
            }

    async def touch(self, key: str, ttl_s: int) -> bool:
        async with self.__dict__["_mu"]:
            touched = False
            new_exp = self._now() + float(ttl_s)
            value_tuple = self._values.get(key)
            if value_tuple:
                resp, _ = value_tuple
                self._values[key] = (resp, new_exp)
                touched = True
            state_tuple = self._states.get(key)
            if state_tuple:
                self._states[key] = (state_tuple[0], new_exp)
                touched = True
            lock_info = self._locks.get(key)
            if lock_info and "expiry" in lock_info:
                lock_info["expiry"] = new_exp
            if touched:
                self._recent_append(key)
                IDEMP_TOUCHES.labels(tenant=self.tenant).inc()
            return touched

    async def bump_replay(
        self,
        key: str,
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
            self._values[key] = (new_resp, value_expiry)
            return new_count


# Backwards-compat name expected by some imports/tests
InMemoryIdemStore = MemoryIdemStore

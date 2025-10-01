"""In-memory idempotency store (test/dev) with ownership & replay bump."""
from __future__ import annotations

import asyncio
import secrets
import time
from typing import Any, Dict, List, Mapping, Optional, Tuple

from app.idempotency.store import IdemStore, StoredResponse


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
        self._states: Dict[str, str] = {}
        # lock info: {"owner": str, "payload_fingerprint": str, "expiry": float}
        self._locks: Dict[str, Dict[str, Any]] = {}
        # recent zset emulation: key -> score(timestamp)
        self._recent: Dict[str, float] = {}

        # Hide lock from type checker; tests use "type: ignore[attr-defined]".
        self.__dict__["_mu"] = asyncio.Lock()

    def _now(self) -> float:
        return time.time()

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
            self._locks[key] = {
                "owner": owner,
                "payload_fingerprint": payload_fingerprint,
                "expiry": self._now() + float(ttl_s),
            }
            self._states[key] = "in_progress"
            self._recent[key] = self._now()
            if (
                self.recent_limit
                and self.recent_limit > 0
                and len(self._recent) > self.recent_limit
            ):
                oldest = sorted(self._recent.items(), key=lambda kv: kv[1])[0][0]
                self._recent.pop(oldest, None)
            return True, owner

    async def get(self, key: str) -> Optional[StoredResponse]:
        async with self.__dict__["_mu"]:
            tup = self._values.get(key)
            return tup[0] if tup else None

    async def put(self, key: str, resp: StoredResponse, ttl_s: int) -> None:  # noqa: ARG002
        async with self.__dict__["_mu"]:
            expiry = self._now() + float(ttl_s)
            self._values[key] = (resp, expiry)
            self._states[key] = "stored"
            self._locks.pop(key, None)

    async def release(self, key: str, owner: Optional[str] = None) -> bool:
        async with self.__dict__["_mu"]:
            info = self._locks.get(key)
            if not info:
                return False
            if owner and info.get("owner") != owner:
                return False
            self._locks.pop(key, None)
            self._states[key] = "released"
            return True

    async def meta(self, key: str) -> Mapping[str, Any]:
        async with self.__dict__["_mu"]:
            info = self._locks.get(key)
            return {
                "state": self._states.get(key),
                "lock": bool(info),
                "payload_fingerprint": info.get("payload_fingerprint") if info else None,
            }

    async def purge(self, key: str) -> bool:
        async with self.__dict__["_mu"]:
            before = any((key in self._values, key in self._states, key in self._locks))
            self._values.pop(key, None)
            self._states.pop(key, None)
            self._locks.pop(key, None)
            return before

    async def list_recent(self, limit: int = 50) -> List[Tuple[str, float]]:
        async with self.__dict__["_mu"]:
            items = sorted(
                self._recent.items(),
                key=lambda kv: kv[1],
                reverse=True,
            )[: max(limit, 0)]
            return [(k, float(v)) for k, v in items]

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
            resp, expiry = tup
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
            new_expiry = (
                self._now() + float(touch_ttl_s) if touch_ttl_s is not None else expiry
            )
            self._values[key] = (new_resp, new_expiry)
            # Touch semantics for memory store: update "recent" and keep state.
            if touch_ttl_s is not None:
                self._states[key] = self._states.get(key, "stored")
                self._recent[key] = self._now()
            return new_count


# Backwards-compat name expected by some imports/tests
InMemoryIdemStore = MemoryIdemStore

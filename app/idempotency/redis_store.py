"""Redis-backed idempotency store with ownership tokens and recent index."""
from __future__ import annotations

import base64
import json
import time
from secrets import token_hex
from typing import Any, Awaitable, List, Mapping, Optional, Tuple, cast

from redis.asyncio import Redis

from app.idempotency.store import IdemStore, StoredResponse


def _ns(ns: str, *parts: str) -> str:
    return ":".join((ns, *parts))


class RedisIdemStore(IdemStore):
    """
    Redis-based idempotency store.

    Keys per user key (K):
      - {ns}:{tenant}:{K}:lock   -> owner token (string)
      - {ns}:{tenant}:{K}:state  -> "in_progress" | "stored" (string)
      - {ns}:{tenant}:{K}:fp     -> payload fingerprint (string)
      - {ns}:{tenant}:{K}:value  -> JSON of StoredResponse
    Also maintains:
      - {ns}:{tenant}:recent     -> ZSET of K with score=epoch seconds
    """

    def __init__(
        self,
        redis: Redis,
        ns: str = "idem",
        tenant: str = "default",
        recent_limit: Optional[int] = None,
    ) -> None:
        self.r = redis
        self.ns = ns
        self.tenant = tenant
        self.recent_limit = recent_limit

    def _k(self, key: str, suffix: str) -> str:
        return _ns(self.ns, self.tenant, key, suffix)

    async def acquire_leader(
        self,
        key: str,
        ttl_s: int,
        payload_fingerprint: str,
    ) -> Tuple[bool, Optional[str]]:
        lock_key = self._k(key, "lock")
        owner = token_hex(16)
        ok = await self.r.set(lock_key, owner, ex=ttl_s, nx=True)
        if ok:
            await self.r.set(self._k(key, "state"), "in_progress", ex=ttl_s)
            await self.r.set(self._k(key, "fp"), payload_fingerprint, ex=ttl_s)
            zkey = _ns(self.ns, self.tenant, "recent")
            now = time.time()
            await self.r.zadd(zkey, {key: now})
            if self.recent_limit and self.recent_limit > 0:
                await self.r.zremrangebyrank(zkey, 0, -self.recent_limit - 1)
            return True, owner
        return False, None

    async def get(self, key: str) -> Optional[StoredResponse]:
        raw = await self.r.get(self._k(key, "value"))
        if not raw:
            return None
        data = json.loads(raw if isinstance(raw, (bytes, bytearray)) else str(raw))
        body = base64.b64decode(data["body_b64"])
        return StoredResponse(
            status=int(data["status"]),
            headers=dict(data["headers"]),
            body=body,
            content_type=data.get("content_type"),
            stored_at=float(data.get("stored_at", 0.0)),
            replay_count=int(data.get("replay_count", 0)),
            body_sha256=str(data.get("body_sha256", "")),
        )

    async def put(self, key: str, resp: StoredResponse, ttl_s: int) -> None:
        norm_headers = {k.lower(): v for k, v in resp.headers.items()}
        value = {
            "status": resp.status,
            "headers": norm_headers,
            "body_b64": base64.b64encode(resp.body).decode("ascii"),
            "content_type": resp.content_type,
            "stored_at": resp.stored_at or time.time(),
            "replay_count": resp.replay_count,
            "body_sha256": resp.body_sha256,
        }
        pipe = self.r.pipeline()
        pipe.set(self._k(key, "value"), json.dumps(value), ex=ttl_s)
        pipe.set(self._k(key, "state"), "stored", ex=ttl_s)
        pipe.expire(self._k(key, "fp"), ttl_s)
        pipe.delete(self._k(key, "lock"))
        await pipe.execute()

    async def release(self, key: str, owner: Optional[str] = None) -> bool:
        """Release lock; if owner given, enforce ownership. Return True if deleted."""
        lock_key = self._k(key, "lock")
        if owner is None:
            return bool(await self.r.delete(lock_key))

        script = """
        local k = KEYS[1]
        local expected = ARGV[1]
        local cur = redis.call('GET', k)
        if cur == expected then
            return redis.call('DEL', k)
        end
        return 0
        """
        res = await cast(Awaitable[Any], self.r.eval(script, 1, lock_key, owner))
        return bool(res)

    async def meta(self, key: str) -> Mapping[str, Any]:
        state = await self.r.get(self._k(key, "state"))
        lock_val = await self.r.get(self._k(key, "lock"))
        fp = await self.r.get(self._k(key, "fp"))
        return {
            "state": (state.decode() if isinstance(state, (bytes, bytearray)) else state),
            "lock": bool(lock_val),
            "payload_fingerprint": (
                fp.decode() if isinstance(fp, (bytes, bytearray)) else fp
            ),
        }

    async def purge(self, key: str) -> bool:
        res = await self.r.delete(
            self._k(key, "value"),
            self._k(key, "state"),
            self._k(key, "lock"),
            self._k(key, "fp"),
        )
        return bool(res)

    async def list_recent(self, limit: int = 50) -> List[Tuple[str, float]]:
        zkey = _ns(self.ns, self.tenant, "recent")
        items = await self.r.zrevrange(zkey, 0, max(limit - 1, 0), withscores=True)
        results: List[Tuple[str, float]] = []
        for raw_key, score in items:
            key = raw_key.decode() if isinstance(raw_key, (bytes, bytearray)) else raw_key
            results.append((key, float(score)))
        return results


"""Redis-backed idempotency store implementation."""

from __future__ import annotations

import base64
import json
import time
from typing import Any, List, Mapping, Optional, Tuple

from redis.asyncio import Redis

from app.idempotency.store import IdemStore, StoredResponse

_ALLOW_HEADERS = {
    "content-type",
    "cache-control",
    "etag",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
    "strict-transport-security",
    "access-control-allow-origin",
    "access-control-expose-headers",
}


def _ns(ns: str, *parts: str) -> str:
    return ":".join((ns, *parts))


class RedisIdemStore(IdemStore):
    """Redis-based idempotency store leveraging ``SET NX`` for single-flight."""

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

    async def acquire_leader(self, key: str, ttl_s: int, payload_fingerprint: str) -> bool:
        lock_key = self._k(key, "lock")
        ok = await self.r.set(lock_key, payload_fingerprint, ex=ttl_s, nx=True)
        if ok:
            state_key = self._k(key, "state")
            await self.r.set(state_key, "in_progress", ex=ttl_s)
            zkey = _ns(self.ns, self.tenant, "recent")
            now = time.time()
            await self.r.zadd(zkey, {key: now})
            if self.recent_limit and self.recent_limit > 0:
                # Keep only the newest ``recent_limit`` entries (higher scores are newer).
                await self.r.zremrangebyrank(zkey, 0, -self.recent_limit - 1)
        return bool(ok)

    async def get(self, key: str) -> Optional[StoredResponse]:
        raw = await self.r.get(self._k(key, "value"))
        if not raw:
            return None
        data = json.loads(raw)
        body = base64.b64decode(data["body_b64"])
        return StoredResponse(
            status=data["status"],
            headers=data["headers"],
            body=body,
            content_type=data.get("content_type"),
            stored_at=data.get("stored_at", 0.0),
            replay_count=data.get("replay_count", 0),
            body_sha256=data.get("body_sha256", ""),
        )

    async def put(self, key: str, resp: StoredResponse, ttl_s: int) -> None:
        filtered_headers = {
            k.lower(): v
            for k, v in resp.headers.items()
            if k.lower() in _ALLOW_HEADERS
        }
        value = {
            "status": resp.status,
            "headers": filtered_headers,
            "body_b64": base64.b64encode(resp.body).decode("ascii"),
            "content_type": resp.content_type,
            "stored_at": resp.stored_at or time.time(),
            "replay_count": resp.replay_count,
            "body_sha256": resp.body_sha256,
        }
        pipe = self.r.pipeline()
        pipe.set(self._k(key, "value"), json.dumps(value), ex=ttl_s)
        pipe.set(self._k(key, "state"), "stored", ex=ttl_s)
        pipe.delete(self._k(key, "lock"))
        await pipe.execute()

    async def release(self, key: str) -> None:
        await self.r.delete(self._k(key, "lock"))

    async def meta(self, key: str) -> Mapping[str, Any]:
        state = await self.r.get(self._k(key, "state"))
        lock_key = self._k(key, "lock")
        lock_value = await self.r.get(lock_key)
        state_text = state.decode() if isinstance(state, bytes) else state
        payload_fp = lock_value.decode() if isinstance(lock_value, bytes) else lock_value
        return {
            "state": state_text,
            "lock": bool(lock_value),
            "payload_fingerprint": payload_fp,
        }

    async def purge(self, key: str) -> bool:
        res = await self.r.delete(
            self._k(key, "value"),
            self._k(key, "state"),
            self._k(key, "lock"),
        )
        return bool(res)

    async def list_recent(self, limit: int = 50) -> List[Tuple[str, float]]:
        zkey = _ns(self.ns, self.tenant, "recent")
        items = await self.r.zrevrange(zkey, 0, max(limit - 1, 0), withscores=True)
        results: List[Tuple[str, float]] = []
        for raw_key, score in items:
            key = raw_key.decode() if isinstance(raw_key, bytes) else raw_key
            results.append((key, float(score)))
        return results

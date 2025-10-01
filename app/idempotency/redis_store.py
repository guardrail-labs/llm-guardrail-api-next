"""Redis-backed idempotency store implementation with owner tokens."""
from __future__ import annotations

import base64
import json
import time
import uuid
from typing import Any, Dict, List, Mapping, Optional, Tuple, cast

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


_LOCK_RELEASE_LUA = """
-- KEYS[1] = lock key
-- ARGV[1] = expected owner token
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
local ok, data = pcall(cjson.decode, raw)
if (not ok) or (data == nil) then return 0 end
if data['owner'] == ARGV[1] then
  return redis.call('DEL', KEYS[1])
else
  return 0
end
"""


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

    async def acquire_leader(
        self, key: str, ttl_s: int, payload_fingerprint: str
    ) -> Tuple[bool, Optional[str]]:
        lock_key = self._k(key, "lock")
        owner = str(uuid.uuid4())
        lock_val = json.dumps({"owner": owner, "payload_fingerprint": payload_fingerprint})
        ok = await self.r.set(lock_key, lock_val, ex=ttl_s, nx=True)
        if ok:
            state_key = self._k(key, "state")
            await self.r.set(state_key, "in_progress", ex=ttl_s)
            zkey = _ns(self.ns, self.tenant, "recent")
            now = time.time()
            await self.r.zadd(zkey, {key: now})
            if self.recent_limit and self.recent_limit > 0:
                # Keep only the newest ``recent_limit`` entries (higher scores are newer).
                await self.r.zremrangebyrank(zkey, 0, -self.recent_limit - 1)
            return True, owner
        return False, None

    async def get(self, key: str) -> Optional[StoredResponse]:
        raw = await self.r.get(self._k(key, "value"))
        if not raw:
            return None
        data: Dict[str, Any]
        if isinstance(raw, bytes):
            data = cast(Dict[str, Any], json.loads(raw))
        else:
            data = cast(Dict[str, Any], json.loads(raw))
        body = base64.b64decode(data["body_b64"])
        return StoredResponse(
            status=int(data["status"]),
            headers=cast(Mapping[str, str], data["headers"]),
            body=body,
            content_type=data.get("content_type"),
            stored_at=float(data.get("stored_at", 0.0)),
            replay_count=int(data.get("replay_count", 0)),
            body_sha256=str(data.get("body_sha256", "")),
        )

    async def put(self, key: str, resp: StoredResponse, ttl_s: int) -> None:
        value = {
            "status": resp.status,
            "headers": {
                k.lower(): v for k, v in resp.headers.items()
                if k.lower() in _ALLOW_HEADERS
            },
            "body_b64": base64.b64encode(resp.body).decode("ascii"),
            "content_type": resp.content_type,
            "stored_at": resp.stored_at or time.time(),
            "replay_count": resp.replay_count,
            "body_sha256": resp.body_sha256,
        }
        pipe = self.r.pipeline()
        pipe.set(self._k(key, "value"), json.dumps(value), ex=ttl_s)
        pipe.set(self._k(key, "state"), "stored", ex=ttl_s)
        # Do not implicitly DEL lock here; the leader should call `release(owner=...)`.
        # But clean up if it still exists (best-effort).
        pipe.delete(self._k(key, "lock"))
        await pipe.execute()

    async def release(self, key: str, owner: Optional[str] = None) -> bool:
        lock_key = self._k(key, "lock")
        if owner:
            try:
                res = await self.r.eval(_LOCK_RELEASE_LUA, 1, lock_key, owner)
                return bool(res)
            except Exception:
                # Fallback best-effort
                pass
        res = await self.r.delete(lock_key)
        # If state was still "in_progress", allow followers to proceed by clearing it.
        state_key = self._k(key, "state")
        cur = await self.r.get(state_key)
        if cur and (cur.decode() if isinstance(cur, bytes) else cur) == "in_progress":
            await self.r.delete(state_key)
        return bool(res)

    async def meta(self, key: str) -> Mapping[str, Any]:
        state = await self.r.get(self._k(key, "state"))
        state_val = state.decode() if isinstance(state, bytes) else state
        lock_raw = await self.r.get(self._k(key, "lock"))
        lock: Optional[Dict[str, Any]] = None
        if lock_raw:
            try:
                lock = json.loads(lock_raw)
            except Exception:
                lock = None

        # ttl_remaining: prefer state key ttl, fallback to lock key
        ttl_state = await self.r.ttl(self._k(key, "state"))
        ttl_lock = await self.r.ttl(self._k(key, "lock"))
        ttl_candidates = [t for t in (ttl_state, ttl_lock) if isinstance(t, int) and t >= 0]
        ttl_remaining = float(min(ttl_candidates)) if ttl_candidates else None

        # also include stored_at / replay_count if a value exists
        val = await self.r.get(self._k(key, "value"))
        stored_at = None
        replay_count = None
        if val:
            try:
                dv = json.loads(val)
                stored_at = float(dv.get("stored_at")) if dv.get("stored_at") is not None else None
                replay_count = int(dv.get("replay_count")) if dv.get("replay_count") is not None else None
            except Exception:
                pass

        return {
            "state": state_val,
            "lock": bool(lock_raw),
            "owner": (lock or {}).get("owner"),
            "payload_fingerprint": (lock or {}).get("payload_fingerprint"),
            "stored_at": stored_at,
            "replay_count": replay_count,
            "ttl_remaining": ttl_remaining,
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

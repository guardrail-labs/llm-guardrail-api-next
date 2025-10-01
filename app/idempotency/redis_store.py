"""Redis-backed idempotency store with ownership tokens and replay bump."""
from __future__ import annotations

import base64
import json
import secrets
import time
from typing import Any, List, Mapping, Optional, Tuple, cast

from redis.asyncio import Redis

from app.idempotency.store import IdemStore, StoredResponse


def _ns(ns: str, *parts: str) -> str:
    return ":".join((ns, *parts))


# Lua: conditional lock release by owner; set state to "released" with TTL.
_RELEASE_LUA = """
local lock_key = KEYS[1]
local state_key = KEYS[2]
local owner = ARGV[1]
local ttl = tonumber(ARGV[2])
local v = redis.call('GET', lock_key)
if not v then
  return 0
end
local decoded = cjson.decode(v)
if decoded and decoded.owner == owner then
  redis.call('DEL', lock_key)
  if ttl and ttl > 0 then
    redis.call('SET', state_key, 'released', 'EX', ttl)
  else
    redis.call('SET', state_key, 'released')
  end
  return 1
end
return 0
"""


# Lua: increment replay_count; refresh TTL to EX if provided else preserve PTTL.
# ARGV[1] = touch ttl seconds or "-1" to preserve PTTL
_BUMP_REPLAY_LUA = """
local value_key = KEYS[1]
local touch_ex = tonumber(ARGV[1])  -- -1 => preserve PTTL
local v = redis.call('GET', value_key)
if not v then
  return nil
end
local obj = cjson.decode(v)
if not obj then
  return nil
end
obj.replay_count = (obj.replay_count or 0) + 1
local new_v = cjson.encode(obj)

if touch_ex and touch_ex >= 0 then
  redis.call('SET', value_key, new_v, 'EX', touch_ex)
else
  local pttl = redis.call('PTTL', value_key)
  if pttl and pttl > 0 then
    redis.call('SET', value_key, new_v, 'PX', pttl)
  else
    redis.call('SET', value_key, new_v)
  end
end

return obj.replay_count
"""


class RedisIdemStore(IdemStore):
    """Redis-based idempotency store leveraging ownership for single-flight."""

    def __init__(
        self,
        redis: Redis,
        ns: str = "idem",
        tenant: str = "default",
        recent_limit: Optional[int] = None,
        release_state_ttl: int = 60,
    ) -> None:
        self.r = redis
        self.ns = ns
        self.tenant = tenant
        self.recent_limit = recent_limit
        self.release_state_ttl = int(release_state_ttl)

    def _k(self, key: str, suffix: str) -> str:
        return _ns(self.ns, self.tenant, key, suffix)

    async def _eval(self, script: str, numkeys: int, *args: str) -> Any:
        """Typed wrapper to satisfy mypy on redis-py's .eval return type."""
        return await cast(Any, self.r).eval(script, numkeys, *args)

    async def acquire_leader(
        self,
        key: str,
        ttl_s: int,
        payload_fingerprint: str,
    ) -> Tuple[bool, Optional[str]]:
        """
        Try to acquire leader lock for this key.
        Value is JSON: {"owner": "<token>", "payload_fingerprint": "<sha256>"}.
        """
        lock_key = self._k(key, "lock")
        owner = secrets.token_urlsafe(16)
        payload = json.dumps(
            {"owner": owner, "payload_fingerprint": payload_fingerprint}
        )
        ok = await self.r.set(lock_key, payload, ex=ttl_s, nx=True)
        if ok:
            state_key = self._k(key, "state")
            await self.r.set(state_key, "in_progress", ex=ttl_s)
            zkey = _ns(self.ns, self.tenant, "recent")
            now = time.time()
            await self.r.zadd(zkey, {key: now})
            if self.recent_limit and self.recent_limit > 0:
                # Keep only the newest ``recent_limit`` entries.
                await self.r.zremrangebyrank(zkey, 0, -self.recent_limit - 1)
            return True, owner
        return False, None

    async def get(self, key: str) -> Optional[StoredResponse]:
        raw = await self.r.get(self._k(key, "value"))
        if not raw:
            return None
        data = json.loads(raw)
        body = base64.b64decode(data["body_b64"])
        headers: Mapping[str, str] = {
            k.lower(): v for k, v in data.get("headers", {}).items()
        }
        return StoredResponse(
            status=int(data["status"]),
            headers=headers,
            body=body,
            content_type=data.get("content_type"),
            stored_at=float(data.get("stored_at", 0.0)),
            replay_count=int(data.get("replay_count", 0)),
            body_sha256=str(data.get("body_sha256", "")),
        )

    async def put(self, key: str, resp: StoredResponse, ttl_s: int) -> None:
        # Persist ALL headers (lower-cased) so custom/security headers replay.
        norm_headers = {k.lower(): v for k, v in resp.headers.items()}
        value = {
            "status": int(resp.status),
            "headers": norm_headers,
            "body_b64": base64.b64encode(resp.body).decode("ascii"),
            "content_type": resp.content_type,
            "stored_at": float(resp.stored_at or time.time()),
            "replay_count": int(resp.replay_count),
            "body_sha256": resp.body_sha256,
        }
        pipe = self.r.pipeline()
        pipe.set(self._k(key, "value"), json.dumps(value), ex=ttl_s)
        pipe.set(self._k(key, "state"), "stored", ex=ttl_s)
        pipe.delete(self._k(key, "lock"))
        await pipe.execute()

    async def release(self, key: str, owner: Optional[str] = None) -> bool:
        """
        Release lock if the owner matches; mark state 'released' briefly.
        Returns True if released, False otherwise.
        """
        lock_key = self._k(key, "lock")
        state_key = self._k(key, "state")
        if not owner:
            res = await self.r.delete(lock_key)
            if res:
                await self.r.set(state_key, "released", ex=self.release_state_ttl)
            return bool(res)
        try:
            ttl = str(self.release_state_ttl)
            res = await self._eval(_RELEASE_LUA, 2, lock_key, state_key, owner, ttl)
        except Exception:
            return False
        return bool(res)

    async def meta(self, key: str) -> Mapping[str, Any]:
        state = await self.r.get(self._k(key, "state"))
        lock_raw = await self.r.get(self._k(key, "lock"))
        state_str = state.decode() if isinstance(state, (bytes, bytearray)) else state
        lock_present = bool(lock_raw)
        payload_fingerprint: Optional[str] = None
        if lock_raw:
            try:
                obj = json.loads(lock_raw)
                payload_fingerprint = obj.get("payload_fingerprint")
            except Exception:
                payload_fingerprint = None
        return {
            "state": state_str,
            "lock": lock_present,
            "payload_fingerprint": payload_fingerprint,
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
            if isinstance(raw_key, (bytes, bytearray)):
                key = raw_key.decode()
            else:
                key = raw_key
            results.append((key, float(score)))
        return results

    async def bump_replay(
        self,
        key: str,
        *,
        touch_ttl_s: Optional[int] = None,
    ) -> Optional[int]:
        """
        Atomically increment replay_count; optionally refresh TTLs and recent.
        Returns the new replay_count, or None if the value does not exist.
        """
        value_key = self._k(key, "value")
        state_key = self._k(key, "state")
        ex = touch_ttl_s if touch_ttl_s is not None else -1
        try:
            new_count = await self._eval(_BUMP_REPLAY_LUA, 1, value_key, str(ex))
        except Exception:
            return None
        if new_count is None:
            return None
        # If we touched, refresh state TTL and 'recent' score as well.
        if touch_ttl_s is not None:
            try:
                await self.r.expire(state_key, touch_ttl_s)
                if self.recent_limit and self.recent_limit > 0:
                    zkey = _ns(self.ns, self.tenant, "recent")
                    await self.r.zadd(zkey, {key: time.time()})
            except Exception:
                pass
        try:
            return int(new_count)
        except Exception:
            return None

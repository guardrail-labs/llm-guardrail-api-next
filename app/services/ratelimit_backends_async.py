from __future__ import annotations

import asyncio
import time
from typing import Any, Optional, Tuple

from app.observability import metrics_ratelimit as _mrl
from app.services.ratelimit_backends import (
    LocalTokenBucket,
    NoScriptError,
    RedisError,
    RedisTokenBucket,
)


class AsyncRedisTokenBucket:
    """Async Redis-backed token bucket mirroring the sync backend semantics."""

    _LUA = RedisTokenBucket._LUA

    def __init__(self, client: Any, prefix: str) -> None:
        self._client = client
        self._prefix = prefix
        self._fallback = LocalTokenBucket()
        self._sha: Optional[str] = None
        self._sha_lock = asyncio.Lock()

    def _key(self, key: str) -> str:
        return f"{self._prefix}{key}"

    def _get_sha(self) -> Optional[str]:
        return self._sha

    async def _set_sha(self, sha_text: str) -> None:
        async with self._sha_lock:
            self._sha = sha_text

    def _sha_to_text(self, sha_value: Any, *, strip: bool) -> str:
        if isinstance(sha_value, bytes):
            sha_text = sha_value.decode()
        elif sha_value is None:
            sha_text = ""
        else:
            sha_text = str(sha_value)
        return sha_text.strip() if strip else sha_text

    async def _store_sha(self, sha_value: Any) -> Optional[str]:
        if sha_value is None:
            return None
        sha_text = self._sha_to_text(sha_value, strip=True)
        if not sha_text:
            raise RedisError("SCRIPT LOAD returned empty SHA")
        async with self._sha_lock:
            self._sha = sha_text
        return sha_text

    async def _best_effort_store_sha(self, sha_value: Any) -> str:
        try:
            stored = await self._store_sha(sha_value)
            if stored:
                return stored
        except Exception:
            pass
        sha_text = self._sha_to_text(sha_value, strip=False)
        await self._set_sha(sha_text)
        return sha_text

    async def _ensure_sha(self) -> str:
        if self._sha:
            return self._sha
        async with self._sha_lock:
            if self._sha:
                return self._sha
            loaded = await self._client.script_load(self._LUA)
            sha_text = self._sha_to_text(loaded, strip=True)
            if not sha_text:
                raise RedisError("SCRIPT LOAD returned empty SHA")
            self._sha = sha_text
            return sha_text

    @staticmethod
    def _is_noscript(exc: Exception) -> bool:
        if isinstance(exc, NoScriptError):
            return True
        try:
            return "NOSCRIPT" in str(exc).upper()
        except Exception:
            return False

    async def _call_script(
        self,
        redis_key: str,
        now: float,
        rps: float,
        burst: float,
        cost: float,
    ) -> Any:
        args = (redis_key, now, float(rps), float(burst), float(cost))

        sha = await self._ensure_sha()

        try:
            return await self._client.evalsha(sha, 1, *args)
        except Exception as exc:
            if not self._is_noscript(exc):
                raise

        try:
            new_sha = await self._client.script_load(self._LUA)
        except Exception:
            return await self._client.eval(self._LUA, 1, *args)

        new_sha_text = await self._best_effort_store_sha(new_sha)

        try:
            result = await self._client.evalsha(new_sha_text, 1, *args)
        except Exception as retry_exc:
            if self._is_noscript(retry_exc):
                return await self._client.eval(self._LUA, 1, *args)
            raise

        _mrl.inc_script_reload()
        return result

    async def allow(
        self,
        key: str,
        *,
        cost: float,
        rps: float,
        burst: float,
    ) -> Tuple[bool, float, Optional[float]]:
        now = time.time()
        redis_key = self._key(key)
        try:
            result = await self._call_script(redis_key, now, rps, burst, cost)
            allowed = int(result[0]) == 1
            retry_after = float(result[1])
            remaining = float(result[2])
            return allowed, retry_after, remaining
        except Exception as exc:
            kind = type(exc).__name__ if isinstance(exc, Exception) else "other"
            _mrl.inc_error(kind)
            _mrl.inc_fallback("redis_error")
            return self._fallback.allow(key, cost=cost, rps=rps, burst=burst)

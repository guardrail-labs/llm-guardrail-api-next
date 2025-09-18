from __future__ import annotations

import logging
import os
import threading
import time
from typing import Callable, Dict, Optional, Tuple

from app.observability import metrics_ratelimit as _mrl

try:  # pragma: no cover - optional dependency during import
    from redis.exceptions import NoScriptError, RedisError
except Exception:  # pragma: no cover
    class NoScriptError(Exception):  # type: ignore[no-redef]
        """Fallback NOSCRIPT error when redis-py is unavailable."""


    class RedisError(Exception):  # type: ignore[no-redef]
        """Fallback Redis error when redis-py is unavailable."""


_log = logging.getLogger(__name__)


class RateLimiterBackend:
    """Interface for rate limit backends."""

    def allow(
        self,
        key: str,
        *,
        cost: float,
        rps: float,
        burst: float,
    ) -> Tuple[bool, float, Optional[float]]:
        """Attempt to spend ``cost`` tokens for ``key``.

        Returns a tuple ``(allowed, retry_after_seconds, remaining_tokens)``.
        ``retry_after_seconds`` is ``0`` when the request is allowed. When the
        backend cannot determine the remaining tokens it should return
        ``None`` for ``remaining_tokens``.
        """

        raise NotImplementedError


class _LocalBucket:
    __slots__ = ("capacity", "refill_rate", "tokens", "last", "lock", "_now")

    def __init__(
        self,
        capacity: float,
        refill_rate: float,
        now: Callable[[], float],
    ) -> None:
        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate)
        self.tokens = float(capacity)
        self._now = now
        self.last = self._now()
        self.lock = threading.Lock()

    def _update_params(self, capacity: float, refill_rate: float) -> None:
        if capacity != self.capacity:
            self.capacity = float(capacity)
            self.tokens = min(self.tokens, self.capacity)
        self.refill_rate = float(refill_rate)

    def update_now(self, now: Callable[[], float]) -> None:
        self._now = now

    def take(self, cost: float, capacity: float, refill_rate: float) -> Tuple[bool, float, float]:
        with self.lock:
            now = self._now()
            self._update_params(capacity, refill_rate)
            if now > self.last:
                delta = now - self.last
                self.tokens = min(self.capacity, self.tokens + delta * self.refill_rate)
                self.last = now
            if self.tokens >= cost:
                self.tokens -= cost
                return True, 0.0, self.tokens
            need = max(0.0, cost - self.tokens)
            if self.refill_rate <= 0.0:
                return False, 1.0, self.tokens
            wait = need / self.refill_rate
            return False, wait, self.tokens


class LocalTokenBucket(RateLimiterBackend):
    """In-process token bucket backend."""

    def __init__(self, now: Optional[Callable[[], float]] = None) -> None:
        self._buckets: Dict[str, _LocalBucket] = {}
        self._lock = threading.Lock()
        self._now = now or time.monotonic

    def _bucket_for(self, key: str, burst: float, rps: float) -> _LocalBucket:
        bucket = self._buckets.get(key)
        if bucket is not None:
            return bucket
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _LocalBucket(burst, rps, self._now)
                self._buckets[key] = bucket
            return bucket

    def set_now(self, now: Callable[[], float]) -> None:
        with self._lock:
            self._now = now
            for bucket in self._buckets.values():
                bucket.update_now(now)

    def allow(
        self,
        key: str,
        *,
        cost: float,
        rps: float,
        burst: float,
    ) -> Tuple[bool, float, Optional[float]]:
        bucket = self._bucket_for(key, burst, rps)
        allowed, retry_after, remaining = bucket.take(cost, burst, rps)
        return allowed, retry_after, remaining


class RedisTokenBucket(RateLimiterBackend):
    """Redis-backed token bucket with an atomic Lua script."""

    _LUA = """
    -- KEYS[1] = hash key
    -- ARGV[1] = now (float seconds)
    -- ARGV[2] = rps (float)
    -- ARGV[3] = burst (float)
    -- ARGV[4] = cost (float)

    local key = KEYS[1]
    local now = tonumber(ARGV[1])
    local rps = tonumber(ARGV[2])
    local burst = tonumber(ARGV[3])
    local cost = tonumber(ARGV[4]) or 1.0

    local data = redis.call('HMGET', key, 'tokens', 'ts')
    local tokens = tonumber(data[1])
    local ts = tonumber(data[2])

    if tokens == nil or ts == nil then
      tokens = burst
      ts = now
    else
      local delta = math.max(now - ts, 0)
      tokens = math.min(burst, tokens + delta * rps)
      ts = now
    end

    local allowed = 0
    local retry_after = 0.0
    if tokens >= cost then
      tokens = tokens - cost
      allowed = 1
    else
      local need = cost - tokens
      if need < 0 then
        need = 0
      end
      local denom = rps
      if denom <= 0 then
        denom = 0.000001
      end
      retry_after = need / denom
    end

    redis.call('HMSET', key, 'tokens', tokens, 'ts', ts)
    local denom = rps
    if denom <= 0 then
      denom = 0.000001
    end
    local ttl = math.max(60, math.floor((burst / denom) * 5))
    redis.call('EXPIRE', key, ttl)

    return {allowed, tostring(retry_after), tostring(tokens)}
    """

    def __init__(self, client, prefix: str, timeout_ms: int = 50) -> None:
        self._client = client
        self._prefix = prefix
        self._timeout = int(timeout_ms)
        self._fallback = LocalTokenBucket()
        try:
            self._sha = self._client.script_load(self._LUA)
        except Exception:
            self._sha = None

    def _key(self, key: str) -> str:
        return f"{self._prefix}{key}"

    def _ensure_sha(self) -> None:
        try:
            if not getattr(self, "_sha", None):
                self._sha = self._client.script_load(self._LUA)
        except Exception:
            self._sha = None

    def _call_script(self, redis_key: str, now: float, rps: float, burst: float, cost: float):
        args = (redis_key, now, float(rps), float(burst), float(cost))

        self._ensure_sha()
        if not self._sha:
            return self._client.eval(self._LUA, 1, *args)

        try:
            return self._client.evalsha(self._sha, 1, *args)
        except NoScriptError:
            _log.warning("Redis NOSCRIPT for rate limit script; attempting reload.")
            try:
                new_sha = self._client.script_load(self._LUA)
                self._sha = new_sha
            except RedisError:
                _log.exception("Redis SCRIPT LOAD failed after NOSCRIPT; denying.")
                raise

            try:
                result = self._client.evalsha(self._sha, 1, *args)
            except NoScriptError:
                _log.exception(
                    "Redis EVALSHA returned NOSCRIPT after reload; denying.",
                )
                raise
            except RedisError:
                _log.exception("Redis EVALSHA failed after reload; denying.")
                raise

            _mrl.inc_script_reload()
            return result
        except Exception:
            pass

        return self._client.eval(self._LUA, 1, *args)

    def allow(
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
            result = self._call_script(redis_key, now, rps, burst, cost)
            allowed = int(result[0]) == 1
            retry_after = float(result[1])
            remaining = float(result[2])
            return allowed, retry_after, remaining
        except Exception as e:
            kind = type(e).__name__ if isinstance(e, Exception) else "other"
            _mrl.inc_error(kind)
            _mrl.inc_fallback("redis_error")
            return self._fallback.allow(key, cost=cost, rps=rps, burst=burst)


def build_backend() -> RateLimiterBackend:
    backend = (os.getenv("RATE_LIMIT_BACKEND") or "local").strip().lower()
    if backend != "redis":
        _mrl.set_backend_in_use("local")
        return LocalTokenBucket()

    url = os.getenv("RATE_LIMIT_REDIS_URL", "redis://localhost:6379/0")
    prefix = os.getenv("RATE_LIMIT_REDIS_KEY_PREFIX", "guardrail:rl:")
    timeout_ms_str = os.getenv("RATE_LIMIT_REDIS_TIMEOUT_MS", "50")
    try:
        timeout_ms = int(timeout_ms_str)
    except Exception:
        timeout_ms = 50

    try:
        import redis

        client = redis.Redis.from_url(url, socket_timeout=timeout_ms / 1000.0)
        backend_obj = RedisTokenBucket(client, prefix=prefix, timeout_ms=timeout_ms)
        _mrl.set_backend_in_use("redis")
        return backend_obj
    except Exception:
        _mrl.set_backend_in_use("local")
        return LocalTokenBucket()


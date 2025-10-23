from __future__ import annotations

from typing import Any

import pytest

from app.middleware.rate_limit import RateLimiter, _scripts


class _DummyRedis:
    def __init__(self) -> None:
        self.tokens: float | None = None
        self.last: float | None = None

    async def evalsha(
        self,
        sha: str,
        numkeys: int,
        key: str,
        capacity: float,
        refill_per_sec: float,
        cost: float,
        now: float,
    ) -> list[Any]:
        if self.tokens is None:
            self.tokens = float(capacity)
            self.last = now
        else:
            elapsed = max(0.0, now - (self.last or now))
            self.tokens = min(float(capacity), float(self.tokens) + elapsed * refill_per_sec)
            self.last = now
        allowed = 0
        if self.tokens >= cost:
            self.tokens -= cost
            allowed = 1
        return [allowed, float(self.tokens)]


@pytest.mark.asyncio
async def test_lua_allows_then_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    dummy = _DummyRedis()
    monkeypatch.setattr("app.middleware.rate_limit.get_redis", lambda: dummy)
    monkeypatch.setattr(_scripts, "rate_token_sha", "sha-test")

    limiter = RateLimiter(capacity=2, per_minute=2)
    bucket = "unit"

    allowed1, _ = await limiter.allow(bucket)
    allowed2, _ = await limiter.allow(bucket)
    allowed3, _ = await limiter.allow(bucket)

    assert allowed1
    assert allowed2
    assert not allowed3

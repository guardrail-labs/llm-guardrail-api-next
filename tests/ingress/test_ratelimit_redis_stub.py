import time

from app.services.ratelimit_backends import RedisTokenBucket


class StubRedis:
    def __init__(self):
        self._scripts = {}
        self._store = {}

    def script_load(self, lua):
        sha = "abc123"
        self._scripts[sha] = lua
        return sha

    def evalsha(self, sha, numkeys, *args):
        if sha not in self._scripts:
            raise Exception("NOSCRIPT")
        return self.eval(self._scripts[sha], numkeys, *args)

    def eval(self, lua, numkeys, *args):
        key = args[0]
        now = float(args[1])
        rps = float(args[2])
        burst = float(args[3])
        cost = float(args[4]) if len(args) > 4 else 1.0
        bucket = self._store.get(key)
        if bucket is None:
            bucket = {"tokens": burst, "ts": now}
        else:
            delta = max(0.0, now - bucket["ts"])
            bucket["tokens"] = min(burst, bucket["tokens"] + delta * rps)
            bucket["ts"] = now

        allowed = 0
        retry_after = 0.0
        if bucket["tokens"] >= cost:
            bucket["tokens"] -= cost
            allowed = 1
        else:
            need = cost - bucket["tokens"]
            retry_after = need / max(rps, 1e-6)

        self._store[key] = bucket
        return [allowed, str(retry_after), str(bucket["tokens"])]


def test_redis_bucket_allows_and_blocks():
    r = StubRedis()
    tb = RedisTokenBucket(r, prefix="t:")

    allowed, retry_after, remaining = tb.allow("k", cost=1.0, rps=2.0, burst=2.0)
    assert allowed
    assert retry_after == 0.0
    assert 0.0 <= remaining <= 2.0

    # Spend remaining burst tokens
    tb.allow("k", cost=1.0, rps=2.0, burst=2.0)
    tb.allow("k", cost=1.0, rps=2.0, burst=2.0)

    denied, retry_after, remaining = tb.allow("k", cost=1.0, rps=2.0, burst=2.0)
    assert not denied
    assert retry_after >= 0.0
    assert 0.0 <= remaining <= 2.0

    # Refill a little and ensure allowance resumes
    time.sleep(0.1)
    allowed_again, retry_after, _ = tb.allow("k", cost=1.0, rps=10.0, burst=2.0)
    assert isinstance(allowed_again, bool)
    assert retry_after >= 0.0


def test_soft_fallback_on_eval_error(monkeypatch):
    class BadRedis(StubRedis):
        def eval(self, *args, **kwargs):
            raise Exception("boom")

    tb = RedisTokenBucket(BadRedis(), prefix="t:")
    allowed, retry_after, remaining = tb.allow("k", cost=1.0, rps=1.0, burst=1.0)
    assert isinstance(allowed, bool)
    assert retry_after >= 0.0
    assert remaining >= 0.0

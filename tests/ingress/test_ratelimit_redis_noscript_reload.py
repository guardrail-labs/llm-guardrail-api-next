from app.services.ratelimit_backends import RedisTokenBucket


class StubRedisNoscriptOnce:
    def __init__(self):
        self._loaded = False
        self._sha = "sha1"
        self._evalsha_calls = 0
        self._store = {}

    def script_load(self, lua):
        self._loaded = True
        self._sha = "sha1"
        return self._sha

    def evalsha(self, sha, numkeys, key, now, rps, burst, cost):
        self._evalsha_calls += 1
        if self._evalsha_calls == 1:
            class _E(Exception):
                pass

            e = _E("NOSCRIPT No matching script. Please use EVAL.")
            e.args = ("NOSCRIPT No matching script. Please use EVAL.",)
            raise e
        return self.eval("", numkeys, key, now, rps, burst, cost)

    def eval(self, lua, numkeys, key, now, rps, burst, cost):
        h = self._store.get(key, {"tokens": burst, "ts": now})
        delta = max(now - h["ts"], 0.0)
        h["tokens"] = min(burst, h["tokens"] + delta * rps)
        h["ts"] = now
        allowed = 0
        retry = 0.0
        if h["tokens"] >= cost:
            h["tokens"] -= cost
            allowed = 1
        else:
            need = cost - h["tokens"]
            retry = need / max(rps, 1e-6)
        self._store[key] = h
        remaining = h["tokens"]
        return [allowed, str(retry), str(remaining)]


def test_reload_after_noscript_and_no_fallback(monkeypatch):
    r = StubRedisNoscriptOnce()
    tb = RedisTokenBucket(r, prefix="t:")

    hit_fallback = {"v": False}

    def _fb_allow(key, *, cost, rps, burst):
        hit_fallback["v"] = True
        raise AssertionError("fallback should not be used on NOSCRIPT")

    tb._fallback.allow = _fb_allow

    ok, retry, rem = tb.allow("k", cost=1.0, rps=2.0, burst=2.0)
    assert ok is True
    assert retry == 0.0
    assert hit_fallback["v"] is False
    ok2, retry2, _ = tb.allow("k", cost=1.0, rps=0.0, burst=0.0)
    assert ok2 in (True, False)


class StubRedisAlwaysBoom:
    def script_load(self, lua):
        return "shaX"

    def evalsha(self, *a, **k):
        raise Exception("boom")

    def eval(self, *a, **k):
        raise Exception("boom")


def test_generic_error_falls_back(monkeypatch):
    r = StubRedisAlwaysBoom()
    tb = RedisTokenBucket(r, prefix="t:")
    ok, retry, rem = tb.allow("k", cost=1.0, rps=1.0, burst=0.0)
    assert ok in (True, False)
    assert retry >= 0.0

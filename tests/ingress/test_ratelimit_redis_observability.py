import sys
import types

from app.services import ratelimit_backends as rb


def make_stub_metrics(monkeypatch):
    from app.observability import metrics_ratelimit as metrics

    calls = {"reload": 0, "error": [], "fallback": [], "backend": None}

    def _inc_reload():
        calls["reload"] += 1

    def _inc_error(kind):
        calls["error"].append(kind)

    def _inc_fallback(reason):
        calls["fallback"].append(reason)

    def _set_backend(name):
        calls["backend"] = name

    monkeypatch.setattr(metrics, "inc_script_reload", _inc_reload)
    monkeypatch.setattr(metrics, "inc_error", _inc_error)
    monkeypatch.setattr(metrics, "inc_fallback", _inc_fallback)
    monkeypatch.setattr(metrics, "set_backend_in_use", _set_backend)
    return calls


def test_noscript_increments_reload(monkeypatch):
    calls = make_stub_metrics(monkeypatch)
    RedisTokenBucket = rb.RedisTokenBucket

    class R:
        def __init__(self):
            self._n = 0

        def script_load(self, lua):
            return "sha"

        def evalsha(self, sha, n, *args):
            self._n += 1
            if self._n == 1:
                raise rb.NoScriptError("NOSCRIPT No matching script.")
            return ["1", "0", "0"]

        def eval(self, *a, **k):
            return ["1", "0", "0"]

    tb = RedisTokenBucket(R(), prefix="t:")
    ok, _, _ = tb.allow("k", cost=1.0, rps=1.0, burst=1.0)
    assert ok is True
    assert calls["reload"] == 1
    assert calls["backend"] is None


def test_error_causes_fallback(monkeypatch):
    calls = make_stub_metrics(monkeypatch)
    RedisTokenBucket = rb.RedisTokenBucket

    class Boom:
        def script_load(self, lua):
            return "sha"

        def evalsha(self, *a, **k):
            raise RuntimeError("boom")

        def eval(self, *a, **k):
            raise RuntimeError("boom")

    tb = RedisTokenBucket(Boom(), prefix="t:")
    ok, _, _ = tb.allow("k", cost=1.0, rps=1.0, burst=0.0)
    assert isinstance(ok, bool)
    assert calls["error"] and "RuntimeError" in calls["error"][0]
    assert calls["fallback"] and calls["fallback"][0] == "redis_error"


def test_backend_gauge_set(monkeypatch):
    from app.observability import metrics_ratelimit as metrics

    calls = {"backend": None}

    def _set_backend(name):
        calls["backend"] = name

    monkeypatch.setattr(metrics, "set_backend_in_use", _set_backend)
    monkeypatch.setenv("RATE_LIMIT_BACKEND", "redis")

    stub_redis = types.SimpleNamespace(
        Redis=types.SimpleNamespace(
            from_url=lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
        )
    )
    monkeypatch.setitem(sys.modules, "redis", stub_redis)

    backend = rb.build_backend()

    assert calls["backend"] in ("redis", "local")
    assert backend is not None

import sys

from app.services.ratelimit_backends import (
    LocalTokenBucket,
    RedisTokenBucket,
    build_backend,
)


def test_build_backend_local_default(monkeypatch):
    monkeypatch.delenv("RATE_LIMIT_BACKEND", raising=False)
    backend = build_backend()
    assert isinstance(backend, LocalTokenBucket)


def test_build_backend_redis_without_lib_falls_back(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_BACKEND", "redis")
    monkeypatch.delenv("RATE_LIMIT_REDIS_URL", raising=False)
    monkeypatch.delenv("RATE_LIMIT_REDIS_KEY_PREFIX", raising=False)
    monkeypatch.delenv("RATE_LIMIT_REDIS_TIMEOUT_MS", raising=False)
    monkeypatch.setitem(sys.modules, "redis", None)
    backend = build_backend()
    assert isinstance(backend, LocalTokenBucket)


def test_build_backend_redis_with_stub(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_BACKEND", "redis")

    class DummyClient:
        def script_load(self, lua):
            return "sha"

        def evalsha(self, *args, **kwargs):
            return [1, "0", "1"]

        def eval(self, *args, **kwargs):
            return [1, "0", "1"]

    class DummyRedisModule:
        class Redis:
            @staticmethod
            def from_url(url, socket_timeout=None):
                return DummyClient()

    monkeypatch.setitem(sys.modules, "redis", DummyRedisModule)
    backend = build_backend()
    assert isinstance(backend, RedisTokenBucket)

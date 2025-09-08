import importlib
import sys
import types

import app.services.verifier as v


def test_memory_cache_default(monkeypatch):
    # Ensure no URL is set so we use memory
    monkeypatch.setenv("VERIFIER_HARM_CACHE_URL", "")
    importlib.reload(v)

    fp = "fp:123"
    assert v.is_known_harmful(fp) is False
    v.mark_harmful(fp)
    assert v.is_known_harmful(fp) is True


def test_redis_cache_path(monkeypatch):
    # Install a fake redis module with the minimal surface we use
    class FakeRedisClient:
        def __init__(self) -> None:
            self.store: dict[str, str] = {}

        def exists(self, key: str) -> int:
            return 1 if key in self.store else 0

        def setex(self, key: str, ttl: int, value: str) -> None:
            # Ignore ttl in fake; just set the key
            self.store[key] = value

    def from_url(url: str, decode_responses: bool = True) -> FakeRedisClient:
        return FakeRedisClient()

    fake_redis = types.SimpleNamespace(from_url=from_url)
    monkeypatch.setitem(sys.modules, "redis", fake_redis)
    monkeypatch.setenv("VERIFIER_HARM_CACHE_URL", "redis://example/0")
    monkeypatch.setenv("VERIFIER_HARM_TTL_DAYS", "90")

    importlib.reload(v)

    fp = "fp:999"
    assert v.is_known_harmful(fp) is False
    v.mark_harmful(fp)
    assert v.is_known_harmful(fp) is True  # via redis -> warms memory path too


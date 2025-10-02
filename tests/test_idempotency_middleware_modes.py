from collections import Counter
from typing import Any, Dict, List, Tuple

import pytest

from app import settings as settings_module
from app.middleware.idempotency import IdempotencyMiddleware
from app.metrics import IDEMP_MISSES
from app.settings import Settings


class RecordingStore:
    def __init__(self) -> None:
        self.calls: List[str] = []

    async def get(self, key: str) -> Any:  # pragma: no cover - behaviour tested via calls
        self.calls.append("get")
        return None

    async def acquire_leader(self, key: str, ttl_s: int, fingerprint: str) -> Tuple[bool, str]:
        self.calls.append("acquire_leader")
        return True, "owner"

    async def meta(self, key: str) -> Dict[str, Any]:
        self.calls.append("meta")
        return {}

    async def put(self, key: str, value: Any, ttl_s: int) -> None:
        self.calls.append("put")

    async def release(self, key: str, owner: str | None = None) -> None:
        self.calls.append("release")

    async def bump_replay(self, key: str) -> int:
        self.calls.append("bump_replay")
        return 1

    async def touch(self, key: str, ttl_s: int) -> None:
        self.calls.append("touch")


async def _dummy_app(scope: Dict[str, Any], receive, send) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": b"{}"})


async def _invoke(
    middleware: IdempotencyMiddleware, path: str = "/resource"
) -> List[Dict[str, Any]]:
    scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": [(b"x-idempotency-key", b"abc123")],
    }
    sent = False

    async def receive() -> Dict[str, Any]:
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": b"{}", "more_body": False}

    messages: List[Dict[str, Any]] = []

    async def send(message: Dict[str, Any]) -> None:
        messages.append(message)

    await middleware(scope, receive, send)
    return messages


def _configure(monkeypatch: pytest.MonkeyPatch, **env: str) -> Settings:
    for key in [
        "APP_ENV",
        "IDEMPOTENCY_MODE",
        "IDEMPOTENCY_EXCLUDE_PATHS",
    ]:
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    effective = Settings().effective()
    settings_module.settings = effective
    settings_module.IDEMP_METHODS = tuple(sorted(effective.idempotency.enforce_methods))
    settings_module.IDEMP_TTL_SECONDS = effective.idempotency.lock_ttl_s
    return effective


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["off", "observe"])
async def test_shadow_modes_skip_store(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    eff = _configure(monkeypatch, APP_ENV="test", IDEMPOTENCY_MODE=mode)
    store = RecordingStore()
    middleware = IdempotencyMiddleware(
        _dummy_app,
        store,
        methods=("POST",),
        tenant_provider=lambda scope: "tenant-test",
    )

    metric = IDEMP_MISSES.labels(
        method="POST", tenant="tenant-test", role="leader", mode=mode
    )
    before = metric._value.get()  # type: ignore[attr-defined]
    messages = await _invoke(middleware)
    after = metric._value.get()  # type: ignore[attr-defined]

    assert store.calls == []
    assert messages[-1]["type"] == "http.response.body"
    assert after - before == pytest.approx(1.0)
    assert eff.idempotency.mode == mode


@pytest.mark.asyncio
async def test_enforce_mode_acquires_and_stores(monkeypatch: pytest.MonkeyPatch) -> None:
    eff = _configure(monkeypatch, APP_ENV="prod")
    store = RecordingStore()
    middleware = IdempotencyMiddleware(
        _dummy_app,
        store,
        methods=("POST",),
        tenant_provider=lambda scope: "tenant-test",
    )

    messages = await _invoke(middleware)

    counts = Counter(store.calls)
    assert counts["acquire_leader"] >= 1
    assert counts["put"] == 1
    assert counts["release"] >= 1
    assert messages[-1]["type"] == "http.response.body"
    assert eff.idempotency.mode == "enforce"


@pytest.mark.asyncio
async def test_excluded_path_bypasses_enforcement(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch, APP_ENV="prod")
    store = RecordingStore()
    middleware = IdempotencyMiddleware(
        _dummy_app,
        store,
        methods=("POST",),
        tenant_provider=lambda scope: "tenant-test",
    )

    await _invoke(middleware, path="/metrics")
    assert store.calls == []

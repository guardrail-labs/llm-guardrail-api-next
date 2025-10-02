"""Idempotency middleware with optional header, owner tokens, and follower backoff."""
from __future__ import annotations

import asyncio
import hashlib
import json
import random
import time
from fnmatch import fnmatch
from typing import Any, Callable, Iterable, Mapping, MutableMapping, Optional, Tuple, Protocol

from starlette.types import ASGIApp, Receive, Scope, Send

from app import settings as settings_module
from app.idempotency.log_utils import log_idempotency_event
from app.idempotency.store import StoredResponse
from app.metrics import (
    IDEMP_BODY_TOO_LARGE,
    IDEMP_CONFLICTS,
    IDEMP_ERRORS,
    IDEMP_HITS,
    IDEMP_IN_PROGRESS,
    IDEMP_LOCK_WAIT,
    IDEMP_MISSES,
    IDEMP_REPLAY_COUNT_HIST,
    IDEMP_REPLAYS,
    IDEMP_STREAMING_SKIPPED,
    metric_counter,
)

# Store protocol to allow test doubles without strict concrete type coupling
class IdemStoreProto(Protocol):
    async def acquire_leader(self, key: str, ttl_s: int, body_fp: str) -> tuple[bool, Optional[str]]: ...
    async def release(self, key: str, owner: Optional[str] = None) -> None: ...
    async def get(self, key: str) -> Optional[StoredResponse]: ...
    async def put(self, key: str, value: StoredResponse, ttl_s: int) -> None: ...
    async def meta(self, key: str) -> Mapping[str, Any]: ...
    async def bump_replay(self, key: str) -> Optional[int]: ...
    async def touch(self, key: str, ttl_s: int) -> None: ...

IDEMP_BACKOFF_STEPS = metric_counter(
    "guardrail_idemp_backoff_steps_total",
    "Backoff steps taken by followers",
    ["mode"],
)


def _mode_label() -> str:
    return settings_module.settings.idempotency.mode


def _is_excluded(path: str) -> bool:
    for pattern in settings_module.settings.idempotency.exclude_paths:
        if fnmatch(path, pattern):
            return True
    return False


class IdempotencyMiddleware:
    def __init__(
        self,
        app: ASGIApp | Callable[..., Any],  # be tolerant for tests
        store: IdemStoreProto,
        ttl_s: Optional[int] = None,
        methods: Optional[Iterable[str]] = None,
        max_body: Optional[int] = None,
        cache_streaming: bool = False,
        tenant_provider: Optional[Callable[[Scope], str]] = None,
        touch_on_replay: Optional[bool] = None,
        wait_budget_ms: Optional[int] = None,
        jitter_ms: Optional[int] = None,
        strict_fail_closed: Optional[bool] = None,
    ) -> None:
        effective = settings_module.settings.idempotency
        self.app = app
        self.store = store
        self.ttl_s = int(ttl_s) if ttl_s is not None else effective.lock_ttl_s
        base_methods: Iterable[str] = methods or tuple(sorted(effective.enforce_methods))
        self.methods = tuple(m.upper() for m in base_methods)
        self.max_body = (
            int(max_body)
            if max_body is not None
            else settings_module.IDEMP_MAX_BODY_BYTES
        )
        self.cache_streaming = cache_streaming
        self.tenant_provider = tenant_provider or (lambda scope: "default")
        self.touch_on_replay = (
            bool(touch_on_replay)
            if touch_on_replay is not None
            else settings_module.IDEMP_TOUCH_ON_REPLAY
        )
        self.wait_budget_s = (
            float(wait_budget_ms) / 1000.0
            if wait_budget_ms is not None
            else effective.wait_budget_ms / 1000.0
        )
        self.max_jitter_s = (
            float(jitter_ms) / 1000.0
            if jitter_ms is not None
            else effective.jitter_ms / 1000.0
        )
        self.strict_fail_closed = (
            bool(strict_fail_closed)
            if strict_fail_closed is not None
            else effective.strict_fail_closed
        )
        self.mask_prefix_len = effective.mask_prefix_len

    def _is_enforced_request(self, mode: str, method: str, path: str) -> bool:
        if mode != "enforce":
            return False
        if method.upper() not in self.methods:
            return False
        if _is_excluded(path):
            return False
        return True

    def _fp_prefix(self, fingerprint: str) -> str:
        return fingerprint[: self.mask_prefix_len]

    def _wait_timeout(self) -> float:
        budget = max(self.wait_budget_s, 0.0)
        if budget <= 0:
            return float(self.ttl_s)
        return float(min(self.ttl_s, budget))

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)  # type: ignore[misc]
            return

        method = scope["method"].upper()
        if method not in self.methods:
            await self.app(scope, receive, send)  # type: ignore[misc]
            return

        tenant = self.tenant_provider(scope)
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        key = headers.get("x-idempotency-key")
        if not key:
            await self.app(scope, receive, send)  # type: ignore[misc]
            return
        if not _valid_key(key):
            await self._send_error(send, 400, "invalid idempotency key")
            return

        body_chunks: list[bytes] = []
        more_body = True
        while more_body:
            msg = await receive()
            if msg["type"] != "http.request":
                continue
            chunk = msg.get("body", b"") or b""
            if chunk:
                body_chunks.append(chunk)
            more_body = bool(msg.get("more_body"))
        body = b"".join(body_chunks)
        body_fp = hashlib.sha256(body).hexdigest()

        mode = _mode_label()
        path = scope.get("path", "")
        if not self._is_enforced_request(mode, method, path):
            IDEMP_MISSES.labels(
                method=method, tenant=tenant, role="leader", mode=mode
            ).inc()
            status, resp_headers, resp_body, _ = await self._run_downstream(scope, body)
            await self._send_fresh(send, status, resp_headers, resp_body)
            return

        try:
            cached = await self.store.get(key)
        except Exception:
            IDEMP_ERRORS.labels(phase="get", mode=mode).inc()
            cached = None

        if cached and cached.body_sha256 == body_fp:
            IDEMP_HITS.labels(
                method=method, tenant=tenant, role="follower", mode=mode
            ).inc()
            await self._send_stored(send, key, cached, method, tenant, mode)
            IDEMP_REPLAYS.labels(
                method=method, tenant=tenant, role="follower", mode=mode
            ).inc()
            return

        IDEMP_MISSES.labels(
            method=method, tenant=tenant, role="leader", mode=mode
        ).inc()

        try:
            ok, owner = await self.store.acquire_leader(key, self.ttl_s, body_fp)
        except Exception

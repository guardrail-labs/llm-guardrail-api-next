"""Idempotency middleware with optional header, owner tokens, and follower backoff."""
from __future__ import annotations

import asyncio
import hashlib
import json
import random
import time
from fnmatch import fnmatch
from typing import Any, Callable, Iterable, Mapping, MutableMapping, Optional, Tuple

from starlette.types import ASGIApp, Receive, Scope, Send

from app import settings as settings_module
from app.idempotency.log_utils import log_idempotency_event
from app.idempotency.store import IdemStore, StoredResponse
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
        app: ASGIApp,
        store: IdemStore,
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
            await self.app(scope, receive, send)
            return

        method = scope["method"].upper()
        if method not in self.methods:
            await self.app(scope, receive, send)
            return

        tenant = self.tenant_provider(scope)
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        key = headers.get("x-idempotency-key")
        if not key:
            await self.app(scope, receive, send)
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
        except Exception:
            IDEMP_ERRORS.labels(phase="acquire", mode=mode).inc()
            ok, owner = False, None

        if ok:
            IDEMP_IN_PROGRESS.labels(tenant=tenant, role="leader", mode=mode).inc()
            log_idempotency_event(
                "leader_acquired",
                key=key,
                tenant=tenant,
                role="leader",
                state="in_progress",
                fp_prefix=self._fp_prefix(body_fp),
            )
            await self._leader_execute_and_persist(key, owner, scope, body, send, mode)
            return

        conflict = False
        try:
            meta = await self.store.meta(key)
        except Exception:
            IDEMP_ERRORS.labels(phase="meta", mode=mode).inc()
            meta = {}
        else:
            fp = meta.get("payload_fingerprint") if isinstance(meta, dict) else None
            if fp and fp != body_fp:
                conflict = True
                IDEMP_CONFLICTS.labels(
                    method=method, tenant=tenant, role="follower", mode=mode
                ).inc()
                log_idempotency_event(
                    "conflict",
                    key=key,
                    tenant=tenant,
                    role="follower",
                    state="conflict",
                    fp_prefix=self._fp_prefix(body_fp),
                )

        if conflict:
            try:
                ok2, owner2 = await self.store.acquire_leader(key, self.ttl_s, body_fp)
            except Exception:
                IDEMP_ERRORS.labels(phase="acquire", mode=mode).inc()
                ok2, owner2 = False, None

            if not ok2:
                wait_start = time.time()
                wait_state = await self._wait_for_release_or_value(
                    key, self._wait_timeout(), mode
                )
                wait_ms = max(time.time() - wait_start, 0.0) * 1000.0
                log_idempotency_event(
                    "follower_wait_complete",
                    key=key,
                    tenant=tenant,
                    role="follower",
                    state=wait_state,
                    fp_prefix=self._fp_prefix(body_fp),
                    wait_ms=wait_ms,
                )
                try:
                    ok2, owner2 = await self.store.acquire_leader(
                        key, self.ttl_s, body_fp
                    )
                except Exception:
                    IDEMP_ERRORS.labels(phase="acquire", mode=mode).inc()
                    ok2, owner2 = False, None

            if ok2:
                IDEMP_IN_PROGRESS.labels(
                    tenant=tenant, role="leader", mode=mode
                ).inc()
                await self._leader_execute_and_persist(
                    key, owner2, scope, body, send, mode
                )
                return

            status, resp_headers, resp_body, _ = await self._run_downstream(scope, body)
            await self._send_fresh(send, status, resp_headers, resp_body)
            return

        start = time.time()
        wait_state = await self._wait_for_release_or_value(
            key, self._wait_timeout(), mode
        )
        duration = max(time.time() - start, 0.0)
        IDEMP_LOCK_WAIT.labels(mode=mode).observe(duration)
        log_idempotency_event(
            "follower_wait_complete",
            key=key,
            tenant=tenant,
            role="follower",
            state=wait_state,
            fp_prefix=self._fp_prefix(body_fp),
            wait_ms=duration * 1000.0,
        )

        try:
            cached_after = await self.store.get(key)
        except Exception:
            IDEMP_ERRORS.labels(phase="get", mode=mode).inc()
            cached_after = None

        if cached_after and cached_after.body_sha256 == body_fp:
            IDEMP_HITS.labels(
                method=method, tenant=tenant, role="follower", mode=mode
            ).inc()
            await self._send_stored(send, key, cached_after, method, tenant, mode)
            IDEMP_REPLAYS.labels(
                method=method, tenant=tenant, role="follower", mode=mode
            ).inc()
            return

        try:
            ok2, owner2 = await self.store.acquire_leader(key, self.ttl_s, body_fp)
        except Exception:
            IDEMP_ERRORS.labels(phase="acquire", mode=mode).inc()
            ok2, owner2 = False, None

        if ok2:
            IDEMP_IN_PROGRESS.labels(tenant=tenant, role="leader", mode=mode).inc()
            await self._leader_execute_and_persist(
                key, owner2, scope, body, send, mode
            )
            return

        status, resp_headers, resp_body, _ = await self._run_downstream(scope, body)
        await self._send_fresh(send, status, resp_headers, resp_body)

    async def _leader_execute_and_persist(
        self,
        key: str,
        owner: Optional[str],
        scope: Scope,
        body: bytes,
        send: Send,
        mode: str,
    ) -> None:
        try:
            status, resp_headers, resp_body, is_streaming = await self._run_downstream(
                scope, body
            )
        except Exception:
            try:
                await self.store.release(key, owner=owner)
            except Exception:
                IDEMP_ERRORS.labels(phase="release", mode=mode).inc()
            await self._send_500(send)
            return

        cacheable = status < 500 and (not is_streaming or self.cache_streaming)
        too_large = len(resp_body) > self.max_body

        if not cacheable or too_large:
            if is_streaming and not self.cache_streaming:
                IDEMP_STREAMING_SKIPPED.labels(mode=mode).inc()
            if too_large:
                IDEMP_BODY_TOO_LARGE.labels(mode=mode).inc()
            try:
                await self.store.release(key, owner=owner)
            except Exception:
                IDEMP_ERRORS.labels(phase="release", mode=mode).inc()
            await self._send_fresh(send, status, resp_headers, resp_body)
            return

        try:
            await self.store.put(
                key,
                StoredResponse(
                    status=status,
                    headers=resp_headers,
                    body=resp_body,
                    content_type=resp_headers.get("content-type"),
                    stored_at=time.time(),
                    replay_count=0,
                    body_sha256=hashlib.sha256(body).hexdigest(),
                ),
                self.ttl_s,
            )
        except Exception:
            IDEMP_ERRORS.labels(phase="put", mode=mode).inc()
        finally:
            try:
                await self.store.release(key, owner=owner)
            except Exception:
                IDEMP_ERRORS.labels(phase="release", mode=mode).inc()

        await self._send_fresh(send, status, resp_headers, resp_body)

    async def _wait_for_release_or_value(self, key: str, timeout: float, mode: str) -> str:
        deadline = time.time() + timeout
        delay = 0.01
        steps = 0
        while time.time() < deadline:
            try:
                if await self.store.get(key):
                    IDEMP_BACKOFF_STEPS.labels(mode=mode).inc()
                    return "value"
            except Exception:
                IDEMP_ERRORS.labels(phase="get", mode=mode).inc()
            try:
                meta = await self.store.meta(key)
                if not meta.get("lock") or meta.get("state") != "in_progress":
                    IDEMP_BACKOFF_STEPS.labels(mode=mode).inc()
                    return "released"
            except Exception:
                IDEMP_ERRORS.labels(phase="meta", mode=mode).inc()

            jitter_cap = self.max_jitter_s if self.max_jitter_s > 0 else 0.05
            jitter = random.random() * min(delay, jitter_cap)
            await asyncio.sleep(delay + jitter)
            delay = min(delay * 2.0, 0.2)
            steps += 1

        if steps:
            IDEMP_BACKOFF_STEPS.labels(mode=mode).inc()
        return "timeout"

    async def _send_error(self, send: Send, status: int, detail: str) -> None:
        payload = json.dumps({"code": "bad_request", "detail": detail}).encode("utf-8")
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode()),
        ]
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": payload})

    async def _send_500(self, send: Send) -> None:
        payload = json.dumps({"detail": "Internal Server Error"}).encode("utf-8")
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode()),
        ]
        await send({"type": "http.response.start", "status": 500, "headers": headers})
        await send({"type": "http.response.body", "body": payload})

    async def _send_fresh(
        self,
        send: Send,
        status: int,
        headers: Mapping[str, str],
        body: bytes,
    ) -> None:
        hdrs = [(k.encode(), v.encode()) for k, v in headers.items()]
        hdrs.append((b"idempotency-replayed", b"false"))
        hdrs.append((b"content-length", str(len(body)).encode()))
        await send({"type": "http.response.start", "status": status, "headers": hdrs})
        await send({"type": "http.response.body", "body": body})

    async def _send_stored(
        self,
        send: Send,
        key: str,
        resp: StoredResponse,
        method: str,
        tenant: str,
        mode: str,
    ) -> None:
        hdrs = [(k.encode(), v.encode()) for k, v in resp.headers.items()]
        hdrs.append((b"idempotency-replayed", b"true"))
        hdrs.append((b"x-idempotency-key", key.encode()))
        replay_count: int | None
        try:
            replay_count = await self.store.bump_replay(key)
        except Exception:
            IDEMP_ERRORS.labels(phase="bump_replay", mode=mode).inc()
            replay_count = None
        else:
            if replay_count is not None:
                resp.replay_count = replay_count
                IDEMP_REPLAY_COUNT_HIST.labels(
                    tenant=tenant, method=method, mode=mode
                ).observe(float(replay_count))
        if self.touch_on_replay:
            try:
                await self.store.touch(key, self.ttl_s)
            except Exception:
                IDEMP_ERRORS.labels(phase="touch", mode=mode).inc()

        count_header: str | None = None
        if replay_count is not None:
            count_header = str(replay_count)
        elif resp.replay_count:
            count_header = str(resp.replay_count)
        if count_header is not None:
            hdrs.append((b"idempotency-replay-count", count_header.encode()))
        body = resp.body
        hdrs.append((b"content-length", str(len(body)).encode()))
        await send({"type": "http.response.start", "status": resp.status, "headers": hdrs})
        await send({"type": "http.response.body", "body": body})

        effective_count = replay_count if replay_count is not None else resp.replay_count or 0
        log_idempotency_event(
            "replay",
            key=key,
            tenant=tenant,
            role="follower",
            state="stored",
            replay_count=effective_count,
            fp_prefix=(resp.body_sha256 or "")[: self.mask_prefix_len],
        )

    async def _run_downstream(
        self,
        scope: Scope,
        body: bytes,
    ) -> Tuple[int, Mapping[str, str], bytes, bool]:
        status_code: Optional[int] = None
        headers: MutableMapping[str, str] = {}
        chunks: list[bytes] = []
        is_streaming = False

        async def receive_wrapper() -> MutableMapping[str, Any]:
            return {"type": "http.request", "body": body, "more_body": False}

        async def send_wrapper(message: MutableMapping[str, Any]) -> None:
            nonlocal status_code, headers, chunks, is_streaming
            if message["type"] == "http.response.start":
                status_code = int(message["status"])
                raw_headers = message.get("headers") or []
                for k, v in raw_headers:
                    headers[k.decode().lower()] = v.decode()
            elif message["type"] == "http.response.body":
                chunk = message.get("body") or b""
                more = bool(message.get("more_body"))
                if more:
                    is_streaming = True
                if chunk:
                    chunks.append(chunk)

        await self.app(scope, receive_wrapper, send_wrapper)
        return int(status_code or 200), headers, b"".join(chunks), is_streaming


def _valid_key(key: str) -> bool:
    if not (1 <= len(key) <= 200):
        return False
    for ch in key:
        if not (ch.isalnum() or ch in "-_"):
            return False
    return True

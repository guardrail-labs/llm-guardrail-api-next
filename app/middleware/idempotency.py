"""Idempotency middleware with env defaults, touches metric, and safe conflict handling."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import random
import time
from typing import Any, Callable, Iterable, Mapping, MutableMapping, Optional, Tuple

from starlette.types import ASGIApp, Receive, Scope, Send

from app.idempotency.store import IdemStore, StoredResponse
from app.metrics import (
    IDEMP_CONFLICTS,
    IDEMP_ERRORS,
    IDEMP_HITS,
    IDEMP_IN_PROGRESS,
    IDEMP_LOCK_WAIT,
    IDEMP_MISSES,
    IDEMP_REPLAYS,
    IDEMP_REPLAY_COUNT,
    IDEMP_TOUCHES,
    metric_counter,
)

IDEMP_BACKOFF_STEPS = metric_counter(
    "guardrail_idemp_backoff_steps_total",
    "Backoff steps taken by followers",
)


def _env_methods() -> Tuple[str, ...]:
    raw = os.environ.get("IDEMP_METHODS")
    if raw:
        return tuple(x.strip().upper() for x in raw.split(",") if x.strip())
    return ("POST",)


def _env_ttl() -> int:
    try:
        return int(os.environ.get("IDEMP_TTL_SECONDS", "120"))
    except Exception:
        return 120


def _env_max_body() -> int:
    try:
        return int(os.environ.get("IDEMP_MAX_BODY_BYTES", str(256 * 1024)))
    except Exception:
        return 256 * 1024


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
        touch_on_replay: bool = False,
    ) -> None:
        self.app = app
        self.store = store
        self.ttl_s = int(ttl_s) if ttl_s is not None else _env_ttl()
        self.methods = tuple(m.upper() for m in (methods or _env_methods()))
        self.max_body = int(max_body) if max_body is not None else _env_max_body()
        self.cache_streaming = cache_streaming
        self.tenant_provider = tenant_provider or (lambda scope: "default")
        self.touch_on_replay = bool(touch_on_replay)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Non-HTTP or method not configured -> pass-through
        if scope.get("type") != "http" or scope.get("method", "").upper() not in self.methods:
            await self.app(scope, receive, send)
            return

        method = scope["method"].upper()
        tenant = self.tenant_provider(scope)

        # Decide on idempotency BEFORE consuming the body to preserve streaming for pass-through.
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        key = headers.get("x-idempotency-key")
        if not key or not _valid_key(key):
            # No/invalid key -> no interception; do not buffer body; preserve streaming.
            await self.app(scope, receive, send)
            return

        # Read body once (bounded later when deciding whether to cache the response).
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

        # Fast path: cached value?
        try:
            cached = await self.store.get(key)
        except Exception:
            IDEMP_ERRORS.labels(phase="get").inc()
            cached = None

        if cached:
            IDEMP_HITS.labels(method=method, tenant=tenant).inc()
            # bump replay count; optionally refresh TTLs inside the store
            try:
                new_count, touched = await self.store.bump_replay(
                    key, touch=self.touch_on_replay
                )
                IDEMP_REPLAY_COUNT.labels(method=method, tenant=tenant).observe(
                    float(new_count)
                )
                if touched:
                    IDEMP_TOUCHES.labels(tenant=tenant).inc()
            except Exception:
                IDEMP_ERRORS.labels(phase="bump").inc()

            await self._send_stored(send, key, cached, replay_count=new_count)
            IDEMP_REPLAYS.labels(method=method, tenant=tenant).inc()
            return

        IDEMP_MISSES.labels(method=method, tenant=tenant).inc()

        # Attempt to become the leader
        try:
            ok, owner = await self.store.acquire_leader(key, self.ttl_s, body_fp)
        except Exception:
            IDEMP_ERRORS.labels(phase="acquire").inc()
            ok, owner = False, None

        if ok:
            IDEMP_IN_PROGRESS.labels(tenant=tenant).inc()
            try:
                status, resp_headers, resp_body, is_streaming = await self._run_downstream(
                    scope, body
                )
            except Exception:
                try:
                    await self.store.release(key, owner=owner)
                except Exception:
                    IDEMP_ERRORS.labels(phase="release").inc()
                raise

            cacheable = (
                status < 500
                and (not is_streaming or self.cache_streaming)
                and len(resp_body) <= self.max_body
            )

            if cacheable:
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
                            body_sha256=body_fp,
                        ),
                        self.ttl_s,
                    )
                except Exception:
                    IDEMP_ERRORS.labels(phase="put").inc()
                finally:
                    try:
                        await self.store.release(key, owner=owner)
                    except Exception:
                        IDEMP_ERRORS.labels(phase="release").inc()
            else:
                try:
                    await self.store.release(key, owner=owner)
                except Exception:
                    IDEMP_ERRORS.labels(phase="release").inc()

            await self._send_fresh(send, status, resp_headers, resp_body)
            return

        # Follower path: check for payload conflict, then wait with backoff.
        conflict = False
        try:
            meta = await self.store.meta(key)
            if isinstance(meta, dict):
                fp = meta.get("payload_fingerprint")
                if fp and fp != body_fp:
                    conflict = True
                    IDEMP_CONFLICTS.labels(method=method, tenant=tenant).inc()
        except Exception:
            IDEMP_ERRORS.labels(phase="meta").inc()

        start = time.time()
        await self._wait_for_release_or_value(key, timeout=self.ttl_s)
        IDEMP_LOCK_WAIT.observe(max(time.time() - start, 0.0))

        try:
            cached_after = await self.store.get(key)
        except Exception:
            IDEMP_ERRORS.labels(phase="get").inc()
            cached_after = None

        # Only replay if no conflict was detected.
        if not conflict and cached_after:
            IDEMP_HITS.labels(method=method, tenant=tenant).inc()
            try:
                new_count, touched = await self.store.bump_replay(
                    key, touch=self.touch_on_replay
                )
                IDEMP_REPLAY_COUNT.labels(method=method, tenant=tenant).observe(
                    float(new_count)
                )
                if touched:
                    IDEMP_TOUCHES.labels(tenant=tenant).inc()
            except Exception:
                IDEMP_ERRORS.labels(phase="bump").inc()

            await self._send_stored(send, key, cached_after, replay_count=new_count)
            IDEMP_REPLAYS.labels(method=method, tenant=tenant).inc()
            return

        # Try to acquire leadership again, otherwise run once.
        try:
            ok2, owner2 = await self.store.acquire_leader(key, self.ttl_s, body_fp)
        except Exception:
            IDEMP_ERRORS.labels(phase="acquire").inc()
            ok2, owner2 = False, None

        if ok2:
            IDEMP_IN_PROGRESS.labels(tenant=tenant).inc()
            try:
                status, resp_headers, resp_body, is_streaming = await self._run_downstream(
                    scope, body
                )
            except Exception:
                try:
                    await self.store.release(key, owner=owner2)
                except Exception:
                    IDEMP_ERRORS.labels(phase="release").inc()
                raise

            cacheable = (
                status < 500
                and (not is_streaming or self.cache_streaming)
                and len(resp_body) <= self.max_body
            )

            if cacheable:
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
                            body_sha256=body_fp,
                        ),
                        self.ttl_s,
                    )
                except Exception:
                    IDEMP_ERRORS.labels(phase="put").inc()
                finally:
                    try:
                        await self.store.release(key, owner=owner2)
                    except Exception:
                        IDEMP_ERRORS.labels(phase="release").inc()
            else:
                try:
                    await self.store.release(key, owner=owner2)
                except Exception:
                    IDEMP_ERRORS.labels(phase="release").inc()

            await self._send_fresh(send, status, resp_headers, resp_body)
            return

        # Final fallback: run once without caching.
        status, resp_headers, resp_body, _ = await self._run_downstream(scope, body)
        await self._send_fresh(send, status, resp_headers, resp_body)

    async def _wait_for_release_or_value(self, key: str, timeout: float) -> str:
        """
        Poll with backoff + jitter until either a cached value appears OR the lock clears.
        Returns "value", "released", or "timeout".
        """
        deadline = time.time() + timeout
        delay = 0.01
        steps = 0
        while time.time() < deadline:
            try:
                if await self.store.get(key):
                    IDEMP_BACKOFF_STEPS.inc()
                    return "value"
            except Exception:
                IDEMP_ERRORS.labels(phase="get").inc()
            try:
                meta = await self.store.meta(key)
                if not meta.get("lock") or meta.get("state") != "in_progress":
                    IDEMP_BACKOFF_STEPS.inc()
                    return "released"
            except Exception:
                IDEMP_ERRORS.labels(phase="meta").inc()
            jitter = random.random() * min(delay, 0.05)
            await asyncio.sleep(delay + jitter)
            delay = min(delay * 2.0, 0.2)
            steps += 1
        if steps:
            IDEMP_BACKOFF_STEPS.inc()
        return "timeout"

    async def _send_error(self, send: Send, status: int, detail: str) -> None:
        payload = json.dumps({"code": "bad_request", "detail": detail}).encode("utf-8")
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode()),
        ]
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": payload})

    async def _send_fresh(
        self,
        send: Send,
        status: int,
        headers: Mapping[str, str],
        body: bytes,
    ) -> None:
        # Ensure replay header is explicitly false
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
        replay_count: int,
    ) -> None:
        hdrs = [(k.encode(), v.encode()) for k, v in resp.headers.items()]
        hdrs.append((b"idempotency-replayed", b"true"))
        hdrs.append((b"x-idempotency-key", key.encode()))
        hdrs.append((b"idempotency-replay-count", str(replay_count).encode()))
        body = resp.body
        hdrs.append((b"content-length", str(len(body)).encode()))
        await send({"type": "http.response.start", "status": resp.status, "headers": hdrs})
        await send({"type": "http.response.body", "body": body})

    async def _run_downstream(
        self, scope: Scope, body: bytes
    ) -> Tuple[int, Mapping[str, str], bytes, bool]:
        """
        Execute downstream app and capture the response.
        Returns (status, headers, body, is_streaming).
        """
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
                if bool(message.get("more_body")):
                    is_streaming = True
                if chunk:
                    chunks.append(chunk)

        await self.app(scope, receive_wrapper, send_wrapper)
        return int(status_code or 200), headers, b"".join(chunks), is_streaming


def _valid_key(key: str) -> bool:
    # 1–200 [A-Za-z0-9_-]
    if not (1 <= len(key) <= 200):
        return False
    for ch in key:
        if not (ch.isalnum() or ch in "-_"):
            return False
    return True

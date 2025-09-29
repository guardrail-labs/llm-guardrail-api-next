"""Idempotency middleware leveraging an asynchronous store."""

from __future__ import annotations

import asyncio
import hashlib
import time
from typing import Awaitable, Callable, Dict, Iterable, Tuple

from starlette.types import Message, Receive, Scope, Send

from app.idempotency.store import IdemStore, StoredResponse
from app.observability.metrics_idempotency import (
    IDEMP_BODY_TOO_LARGE,
    IDEMP_CONFLICTS,
    IDEMP_ERRORS,
    IDEMP_EVICTIONS,
    IDEMP_HITS,
    IDEMP_IN_PROGRESS,
    IDEMP_LOCK_WAIT,
    IDEMP_MISSES,
    IDEMP_REPLAYS,
    IDEMP_STREAMING_SKIPPED,
)

ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]
_VALID = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")


def _valid_key(s: str) -> bool:
    if not (1 <= len(s) <= 200):
        return False
    return all(ch in _VALID for ch in s)


def _sha256(data: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(data)
    return digest.hexdigest()


class IdempotencyMiddleware:
    """Replay identical requests based on idempotency key + body fingerprint."""

    def __init__(
        self,
        app: ASGIApp,
        store: IdemStore,
        *,
        ttl_s: int,
        methods: Iterable[str],
        max_body: int,
        cache_streaming: bool,
        tenant_provider: Callable[[Scope], str] = lambda scope: "default",
    ) -> None:
        self.app = app
        self.store = store
        self.ttl_s = ttl_s
        self.methods = {m.upper() for m in methods}
        self.max_body = max_body
        self.cache_streaming = cache_streaming
        self.tenant_provider = tenant_provider

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "GET").upper()
        if method not in self.methods:
            await self.app(scope, receive, send)
            return

        raw_headers: Iterable[Tuple[bytes, bytes]] = scope.get("headers") or []
        headers = {k.decode("latin1"): v.decode("latin1") for k, v in raw_headers}
        key = headers.get("x-idempotency-key")
        if not key or not _valid_key(key):
            await self._send_bad_request(send)
            return

        tenant = self.tenant_provider(scope)

        body = await self._receive_body(receive)
        body_len = len(body)
        body_fp = _sha256(body)

        cached = None
        try:
            cached = await self.store.get(key)
        except Exception:
            IDEMP_ERRORS.labels(phase="get").inc()
        else:
            if cached and cached.body_sha256 and cached.body_sha256 != body_fp:
                IDEMP_CONFLICTS.labels(method=method, tenant=tenant).inc()
                cached = None

        if cached:
            IDEMP_HITS.labels(method=method, tenant=tenant).inc()
            await self._send_stored(send, key, cached)
            IDEMP_REPLAYS.labels(method=method, tenant=tenant).inc()
            return

        IDEMP_MISSES.labels(method=method, tenant=tenant).inc()

        cacheable = body_len <= self.max_body
        if not cacheable:
            IDEMP_BODY_TOO_LARGE.labels(tenant=tenant).inc()

        leader = False
        try:
            leader = await self.store.acquire_leader(key, self.ttl_s, body_fp)
        except Exception:
            IDEMP_ERRORS.labels(phase="acquire").inc()

        if leader:
            IDEMP_IN_PROGRESS.labels(tenant=tenant).inc()
            try:
                try:
                    (
                        status,
                        resp_headers,
                        resp_body,
                        is_streaming,
                    ) = await self._run_downstream(scope, body)
                except Exception:
                    await self._safe_release(key, tenant, "exception")
                    raise

                if is_streaming and not self.cache_streaming:
                    IDEMP_STREAMING_SKIPPED.labels(method=method, tenant=tenant).inc()
                    await self._send_raw(send, key, status, resp_headers, resp_body, replay=False)
                    await self._safe_release(key, tenant, "streaming")
                    return

                if cacheable and 200 <= status < 500:
                    stored = StoredResponse(
                        status=status,
                        headers=resp_headers,
                        body=resp_body,
                        content_type=resp_headers.get("content-type"),
                        stored_at=time.time(),
                        body_sha256=body_fp,
                    )
                    try:
                        await self.store.put(key, stored, self.ttl_s)
                    except Exception:
                        IDEMP_ERRORS.labels(phase="put").inc()
                        await self._safe_release(key, tenant, "put_error")
                else:
                    reason = "upstream_error" if status >= 500 else "not_cached"
                    await self._safe_release(key, tenant, reason)
                await self._send_raw(send, key, status, resp_headers, resp_body, replay=False)
            finally:
                IDEMP_IN_PROGRESS.labels(tenant=tenant).dec()
        else:
            try:
                meta = await self.store.meta(key)
            except Exception:
                IDEMP_ERRORS.labels(phase="meta").inc()
                meta = {}
            else:
                fingerprint = meta.get("payload_fingerprint") if isinstance(meta, dict) else None
                if fingerprint and fingerprint != body_fp:
                    IDEMP_CONFLICTS.labels(method=method, tenant=tenant).inc()

            start = time.time()
            await self._wait_for_value(key, timeout=self.ttl_s)
            IDEMP_LOCK_WAIT.observe(max(time.time() - start, 0.0))
            try:
                cached_after = await self.store.get(key)
            except Exception:
                IDEMP_ERRORS.labels(phase="get").inc()
                cached_after = None
            if cached_after:
                IDEMP_HITS.labels(method=method, tenant=tenant).inc()
                await self._send_stored(send, key, cached_after)
                IDEMP_REPLAYS.labels(method=method, tenant=tenant).inc()
            else:
                status, resp_headers, resp_body, _ = await self._run_downstream(scope, body)
                await self._send_raw(send, key, status, resp_headers, resp_body, replay=False)

    async def _safe_release(self, key: str, tenant: str, reason: str) -> None:
        try:
            await self.store.release(key)
        except Exception:
            IDEMP_ERRORS.labels(phase="release").inc()
        IDEMP_EVICTIONS.labels(tenant=tenant, reason=reason).inc()

    async def _receive_body(self, receive: Receive) -> bytes:
        body_chunks = []
        more = True
        while more:
            message = await receive()
            if message["type"] == "http.request":
                chunk = message.get("body", b"") or b""
                if chunk:
                    body_chunks.append(chunk)
                more = bool(message.get("more_body"))
            elif message["type"] == "http.disconnect":
                break
        return b"".join(body_chunks)

    async def _wait_for_value(self, key: str, timeout: int) -> None:
        deadline = time.time() + timeout
        delay = 0.01
        while time.time() < deadline:
            try:
                if await self.store.get(key):
                    return
            except Exception:
                IDEMP_ERRORS.labels(phase="get").inc()
                return
            await asyncio.sleep(delay)
            delay = min(delay * 2, 0.2)

    async def _run_downstream(
        self, scope: Scope, body: bytes
    ) -> Tuple[int, Dict[str, str], bytes, bool]:
        resp_headers: Dict[str, str] = {}
        body_chunks = []
        is_streaming = False
        status_holder = {"code": 200}

        async def send_wrapper(message: Message) -> None:
            nonlocal is_streaming
            if message["type"] == "http.response.start":
                status_holder["code"] = int(message.get("status", 200))
                for name, value in message.get("headers", []) or []:
                    resp_headers[name.decode("latin1").lower()] = value.decode("latin1")
            elif message["type"] == "http.response.body":
                if message.get("more_body"):
                    is_streaming = True
                chunk = message.get("body", b"") or b""
                if chunk:
                    body_chunks.append(chunk)

        async def receive_wrapper() -> Message:
            if receive_wrapper._sent:
                return {"type": "http.request", "body": b"", "more_body": False}
            receive_wrapper._sent = True
            return {"type": "http.request", "body": body, "more_body": False}

        receive_wrapper._sent = False  # type: ignore[attr-defined]

        await self.app(scope, receive_wrapper, send_wrapper)
        return status_holder["code"], resp_headers, b"".join(body_chunks), is_streaming

    async def _send_bad_request(self, send: Send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 400,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": b'{"code":"bad_request","detail":"invalid idempotency key"}',
            }
        )

    async def _send_stored(self, send: Send, key: str, stored: StoredResponse) -> None:
        headers = [(k.encode("latin1"), v.encode("latin1")) for k, v in stored.headers.items()]
        headers.append((b"idempotency-key", key.encode("latin1")))
        headers.append((b"idempotency-replayed", b"true"))
        await send({"type": "http.response.start", "status": stored.status, "headers": headers})
        await send({"type": "http.response.body", "body": stored.body})

    async def _send_raw(
        self,
        send: Send,
        key: str,
        status: int,
        headers: Dict[str, str],
        body: bytes,
        *,
        replay: bool,
    ) -> None:
        hdrs = [(k.encode("latin1"), v.encode("latin1")) for k, v in headers.items()]
        hdrs.append((b"idempotency-key", key.encode("latin1")))
        hdrs.append((b"idempotency-replayed", b"true" if replay else b"false"))
        await send({"type": "http.response.start", "status": status, "headers": hdrs})
        await send({"type": "http.response.body", "body": body})

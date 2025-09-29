"""ASGI Idempotency middleware with Redis-backed store support."""

from __future__ import annotations

import asyncio
import hashlib
import time
from typing import (
    Dict,
    Iterable,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
    cast,
)

from app.idempotency.store import IdemStore, StoredResponse
from app.observability.metrics_idempotency import (
    IDEMP_BODY_TOO_LARGE,
    IDEMP_CONFLICTS,
    IDEMP_ERRORS,
    IDEMP_HITS,
    IDEMP_IN_PROGRESS,
    IDEMP_LOCK_WAIT,
    IDEMP_MISSES,
    IDEMP_REPLAYS,
    IDEMP_STREAMING_SKIPPED,
)

_VALID_CHARS = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
)


def _valid_key(s: str) -> bool:
    if not (1 <= len(s) <= 200):
        return False
    return all(ch in _VALID_CHARS for ch in s)


def _sha256(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()


class IdempotencyMiddleware:
    def __init__(
        self,
        app,
        store: IdemStore,
        *,
        ttl_s: int,
        methods: Iterable[str],
        max_body: int,
        cache_streaming: bool,
        tenant_provider=lambda scope: "default",
    ) -> None:
        self.app = app
        self.store = store
        self.ttl_s = ttl_s
        self.methods = {m.upper() for m in methods}
        self.max_body = max_body
        self.cache_streaming = cache_streaming
        self.tenant_provider = tenant_provider

    async def __call__(self, scope, receive, send):
        # Only apply to configured HTTP methods.
        if scope.get("type") != "http" or scope.get("method", "").upper() not in self.methods:
            await self.app(scope, receive, send)
            return

        # Normalize headers into a case-insensitive dict (lowercased keys).
        hdrs: Dict[str, str] = {}
        for k, v in scope.get("headers", []):
            hdrs[k.decode("latin1").lower()] = v.decode("latin1")

        idem_key = hdrs.get("x-idempotency-key")

        # If no key is present, no-op: do not consume the body; pass through.
        if not idem_key:
            await self.app(scope, receive, send)
            return

        # If key is present but invalid, reject.
        if not _valid_key(idem_key):
            await self._send_bad_request(send)
            return

        tenant = self.tenant_provider(scope)
        method = scope["method"].upper()

        # Buffer request body for fingerprinting only when key is present.
        body = await self._read_request_body(receive)
        body_len = len(body)
        body_fp = _sha256(body)

        # If already stored and body fingerprint matches, replay; else miss.
        try:
            cached = await self.store.get(idem_key)
        except Exception:
            IDEMP_ERRORS.labels(phase="get").inc()
            cached = None

        if cached and (not cached.body_sha256 or cached.body_sha256 == body_fp):
            IDEMP_HITS.labels(method=method, tenant=tenant).inc()
            await self._send_stored(send, idem_key, cached)
            IDEMP_REPLAYS.labels(method=method, tenant=tenant).inc()
            return

        IDEMP_MISSES.labels(method=method, tenant=tenant).inc()

        # Size policy: large bodies are deduped in-flight but not cached.
        cacheable = body_len <= self.max_body
        if not cacheable:
            IDEMP_BODY_TOO_LARGE.labels(tenant=tenant).inc()

        # Try to become leader for single-flight.
        try:
            leader = await self.store.acquire_leader(idem_key, self.ttl_s, body_fp)
        except Exception:
            IDEMP_ERRORS.labels(phase="acquire").inc()
            leader = False

        if leader:
            IDEMP_IN_PROGRESS.labels(tenant=tenant).inc()
            try:
                status, resp_headers, resp_body, is_streaming = await self._run_downstream(
                    scope, body
                )

                # Streaming policy: dedupe only, do not cache.
                if is_streaming and not self.cache_streaming:
                    IDEMP_STREAMING_SKIPPED.labels(method=method, tenant=tenant).inc()
                    await self._send_raw(
                        send, status, resp_headers, resp_body, replay=False, idem_key=idem_key
                    )
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
                        await self.store.put(idem_key, stored, self.ttl_s)
                    except Exception:
                        IDEMP_ERRORS.labels(phase="put").inc()
                elif status >= 500:
                    # Ensure retry can proceed.
                    await self.store.release(idem_key)

                await self._send_raw(
                    send, status, resp_headers, resp_body, replay=False, idem_key=idem_key
                )
            finally:
                IDEMP_IN_PROGRESS.labels(tenant=tenant).dec()
            return

        # Follower path: another request currently executing for this key.
        mismatch = False
        try:
            meta = await self.store.meta(idem_key)
        except Exception:
            IDEMP_ERRORS.labels(phase="meta").inc()
            meta = {}
        else:
            fp = meta.get("payload_fingerprint") if isinstance(meta, dict) else None
            if fp and fp != body_fp:
                IDEMP_CONFLICTS.labels(method=method, tenant=tenant).inc()
                mismatch = True

        start = time.time()
        # Wait until either a value appears OR the lock/state indicates leader finished.
        await self._wait_for_release_or_value(idem_key, timeout=self.ttl_s)
        IDEMP_LOCK_WAIT.observe(max(time.time() - start, 0.0))

        if mismatch:
            # Do NOT replay. Try to become leader now that lock is gone.
            try:
                leader2 = await self.store.acquire_leader(idem_key, self.ttl_s, body_fp)
            except Exception:
                IDEMP_ERRORS.labels(phase="acquire").inc()
                leader2 = False

            if leader2:
                IDEMP_IN_PROGRESS.labels(tenant=tenant).inc()
                try:
                    status, resp_headers, resp_body, is_streaming = await self._run_downstream(
                        scope, body
                    )
                    if not (is_streaming and not self.cache_streaming) and (
                        200 <= status < 500 and cacheable
                    ):
                        stored2 = StoredResponse(
                            status=status,
                            headers=resp_headers,
                            body=resp_body,
                            content_type=resp_headers.get("content-type"),
                            stored_at=time.time(),
                            body_sha256=body_fp,
                        )
                        try:
                            await self.store.put(idem_key, stored2, self.ttl_s)
                        except Exception:
                            IDEMP_ERRORS.labels(phase="put").inc()
                    elif status >= 500:
                        await self.store.release(idem_key)

                    await self._send_raw(
                        send, status, resp_headers, resp_body, replay=False, idem_key=idem_key
                    )
                finally:
                    IDEMP_IN_PROGRESS.labels(tenant=tenant).dec()
                return

            # If someone else re-acquired, execute once without caching to avoid
            # replaying a response for the wrong payload.
            status, resp_headers, resp_body, _ = await self._run_downstream(scope, body)
            await self._send_raw(
                send, status, resp_headers, resp_body, replay=False, idem_key=idem_key
            )
            return

        # No mismatch: safe to replay if value is present; otherwise run once.
        try:
            cached_after = await self.store.get(idem_key)
        except Exception:
            IDEMP_ERRORS.labels(phase="get").inc()
            cached_after = None

        if cached_after:
            IDEMP_HITS.labels(method=method, tenant=tenant).inc()
            await self._send_stored(send, idem_key, cached_after)
            IDEMP_REPLAYS.labels(method=method, tenant=tenant).inc()
            return

        status, resp_headers, resp_body, _ = await self._run_downstream(scope, body)
        await self._send_raw(
            send, status, resp_headers, resp_body, replay=False, idem_key=idem_key
        )

    async def _wait_for_release_or_value(self, key: str, timeout: int) -> None:
        """
        Wait until either:
          - a cached value appears for `key`, OR
          - the lock is gone / state != "in_progress" (leader finished).
        This prevents followers from stalling full TTL when leader doesn't cache.
        """
        deadline = time.time() + timeout
        delay = 0.01
        while time.time() < deadline:
            try:
                # If a value exists, we're done.
                if await self.store.get(key):
                    return
                # Otherwise, peek at meta: if no lock or not "in_progress", leader is done.
                meta = await self.store.meta(key)
                if isinstance(meta, dict):
                    lock_present = bool(meta.get("lock"))
                    state_text = meta.get("state")
                    if (not lock_present) or (state_text != "in_progress"):
                        return
            except Exception:
                IDEMP_ERRORS.labels(phase="wait").inc()
            await asyncio.sleep(delay)
            delay = min(delay * 2, 0.2)

    async def _read_request_body(self, receive) -> bytes:
        """Drain the ASGI receive channel into a single bytes object."""
        chunks: list[bytes] = []
        more = True
        while more:
            msg: MutableMapping[str, object] = await receive()
            if msg.get("type") == "http.request":
                body = msg.get("body")
                if isinstance(body, (bytes, bytearray)):
                    chunks.append(bytes(body))
                more = bool(msg.get("more_body", False))
            else:
                more = False
        return b"".join(chunks)

    async def _run_downstream(
        self, scope, body: bytes
    ) -> Tuple[int, Dict[str, str], bytes, bool]:
        """Replay buffered body to the app and capture the full response."""
        resp_headers: Dict[str, str] = {}
        body_chunks: list[bytes] = []
        is_streaming = False
        status_holder = {"code": 200}

        async def send_wrapper(msg: Mapping[str, object]) -> None:
            nonlocal is_streaming
            if msg.get("type") == "http.response.start":
                status = msg.get("status")
                if isinstance(status, int):
                    status_holder["code"] = status
                raw_headers_obj = msg.get("headers")
                raw_headers = cast(
                    Optional[Sequence[Tuple[bytes, bytes]]],
                    raw_headers_obj,
                )
                if raw_headers:
                    for k, v in raw_headers:
                        resp_headers[k.decode("latin1").lower()] = v.decode("latin1")
            elif msg.get("type") == "http.response.body":
                if msg.get("more_body"):
                    is_streaming = True
                b = msg.get("body")
                if isinstance(b, (bytes, bytearray)) and b:
                    body_chunks.append(bytes(b))

        # Provide the buffered body once, then EOF.
        sent = False

        async def receive_wrapper() -> MutableMapping[str, object]:
            nonlocal sent
            if sent:
                return {"type": "http.request", "body": b"", "more_body": False}
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, receive_wrapper, send_wrapper)
        return status_holder["code"], resp_headers, b"".join(body_chunks), is_streaming

    async def _send_bad_request(self, send) -> None:
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

    async def _send_stored(
        self, send, key: str, stored: StoredResponse
    ) -> None:
        headers = [
            (k.encode("latin1"), v.encode("latin1"))
            for k, v in stored.headers.items()
        ]
        headers.append((b"idempotency-replayed", b"true"))
        headers.append((b"x-idempotency-key", key.encode("latin1")))
        await send(
            {
                "type": "http.response.start",
                "status": stored.status,
                "headers": headers,
            }
        )
        await send({"type": "http.response.body", "body": stored.body})

    async def _send_raw(
        self,
        send,
        status: int,
        headers_dict: Mapping[str, str],
        body: bytes,
        *,
        replay: bool,
        idem_key: Optional[str],
    ) -> None:
        headers = [
            (k.encode("latin1"), v.encode("latin1"))
            for k, v in headers_dict.items()
        ]
        if idem_key is not None:
            headers.append(
                (b"idempotency-replayed", b"true" if replay else b"false")
            )
            headers.append((b"x-idempotency-key", idem_key.encode("latin1")))
        await send(
            {"type": "http.response.start", "status": status, "headers": headers}
        )
        await send({"type": "http.response.body", "body": body})

"""Idempotency middleware with conflict handling, TTL touch, and safe metrics."""
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
    IDEMP_REPLAY_COUNT_HIST,
    metric_counter,
)

# No-label counter; track follower backoff steps for observability.
IDEMP_BACKOFF_STEPS = metric_counter(
    "guardrail_idemp_backoff_steps_total",
    "Backoff steps taken by followers",
)


# ------------------------- env helpers -------------------------


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


# ------------------------- metric helpers -------------------------


def _labelnames(metric: Any) -> tuple[str, ...]:
    try:
        names = getattr(metric, "_labelnames", ())
        if names is None:
            return ()
        return tuple(names)
    except Exception:
        return ()


def _safe_labels(metric: Any, labels: Optional[Mapping[str, str]]) -> Any:
    names = _labelnames(metric)
    if not names:
        return metric
    lab = dict(labels or {})
    lab = {k: v for k, v in lab.items() if k in names}
    for n in names:
        if n not in lab:
            lab[n] = "unknown"
    return metric.labels(**lab)


def _safe_inc(metric: Any, labels: Optional[Mapping[str, str]] = None) -> None:
    try:
        _safe_labels(metric, labels).inc()
    except Exception:
        pass


def _safe_observe(
    metric: Any, value: float, labels: Optional[Mapping[str, str]] = None
) -> None:
    try:
        _safe_labels(metric, labels).observe(value)
    except Exception:
        pass


# ------------------------- middleware -------------------------


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
        touch_on_replay: bool = True,
    ) -> None:
        self.app = app
        self.store = store
        self.ttl_s = int(ttl_s) if ttl_s is not None else _env_ttl()
        self.methods = tuple(m.upper() for m in (methods or _env_methods()))
        self.max_body = int(max_body) if max_body is not None else _env_max_body()
        self.cache_streaming = cache_streaming
        self.tenant_provider = tenant_provider or (lambda scope: "default")
        self.touch_on_replay = touch_on_replay

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        method = (scope.get("method") or "GET").upper()
        if method not in self.methods:
            await self.app(scope, receive, send)
            return

        tenant = self.tenant_provider(scope)
        headers = {
            (k or b"").decode().lower(): (v or b"").decode()
            for (k, v) in scope.get("headers", [])
        }
        key = headers.get("x-idempotency-key")

        # If no key provided: pass-through (preserve streaming semantics).
        if not key:
            await self.app(scope, receive, send)
            return

        if not _valid_key(key):
            await self._send_error(send, 400, "invalid idempotency key")
            return

        # Read/clone body once so we can hash + forward it.
        body = await self._read_body(receive)
        body_fp = hashlib.sha256(body).hexdigest()

        # Fast path: cached?
        try:
            cached = await self.store.get(key)
        except Exception:
            _safe_inc(IDEMP_ERRORS, {"phase": "get"})
            cached = None

        if cached is not None:
            # If cached payload fingerprint doesn't match, treat as conflict (fresh response).
            cached_fp = getattr(cached, "body_sha256", None)
            if cached_fp and cached_fp != body_fp:
                _safe_inc(IDEMP_CONFLICTS, {"method": method, "tenant": tenant})
                status, resp_headers, resp_body, _ = await self._run_downstream(
                    scope, body
                )
                await self._send_fresh(send, status, resp_headers, resp_body)
                return

            _safe_inc(IDEMP_HITS, {"method": method, "tenant": tenant})
            count = await self._on_replay(key, method, tenant)
            await self._send_stored(send, key, cached, replay_count=count)
            _safe_inc(IDEMP_REPLAYS, {"method": method, "tenant": tenant})
            return

        _safe_inc(IDEMP_MISSES, {"method": method, "tenant": tenant})

        # Try to become leader.
        try:
            ok, owner = await self.store.acquire_leader(key, self.ttl_s, body_fp)
        except Exception:
            _safe_inc(IDEMP_ERRORS, {"phase": "acquire"})
            ok, owner = False, None

        if ok:
            _safe_inc(IDEMP_IN_PROGRESS, {"tenant": tenant})
            # Leader: run and maybe cache.
            try:
                status, resp_headers, resp_body, is_streaming = await self._run_downstream(
                    scope, body
                )
            except Exception:
                try:
                    await self.store.release(key, owner=owner)
                except Exception:
                    _safe_inc(IDEMP_ERRORS, {"phase": "release"})
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
                    _safe_inc(IDEMP_ERRORS, {"phase": "put"})
                finally:
                    try:
                        await self.store.release(key, owner=owner)
                    except Exception:
                        _safe_inc(IDEMP_ERRORS, {"phase": "release"})
            else:
                try:
                    await self.store.release(key, owner=owner)
                except Exception:
                    _safe_inc(IDEMP_ERRORS, {"phase": "release"})

            await self._send_fresh(send, status, resp_headers, resp_body)
            return

        # Follower path: detect payload conflict before waiting.
        try:
            meta = await self.store.meta(key)
        except Exception:
            _safe_inc(IDEMP_ERRORS, {"phase": "meta"})
            meta = {}
        else:
            fp = meta.get("payload_fingerprint") if isinstance(meta, dict) else None
            if fp and fp != body_fp:
                _safe_inc(IDEMP_CONFLICTS, {"method": method, "tenant": tenant})
                status, resp_headers, resp_body, _ = await self._run_downstream(
                    scope, body
                )
                await self._send_fresh(send, status, resp_headers, resp_body)
                return

        start = time.time()
        await self._wait_for_release_or_value(key, timeout=self.ttl_s)
        _safe_observe(IDEMP_LOCK_WAIT, max(time.time() - start, 0.0))

        try:
            cached_after = await self.store.get(key)
        except Exception:
            _safe_inc(IDEMP_ERRORS, {"phase": "get"})
            cached_after = None

        if cached_after is not None:
            # Safety: fingerprint check again.
            cached_fp = getattr(cached_after, "body_sha256", None)
            if cached_fp and cached_fp != body_fp:
                _safe_inc(IDEMP_CONFLICTS, {"method": method, "tenant": tenant})
                status, resp_headers, resp_body, _ = await self._run_downstream(
                    scope, body
                )
                await self._send_fresh(send, status, resp_headers, resp_body)
                return

            _safe_inc(IDEMP_HITS, {"method": method, "tenant": tenant})
            count = await self._on_replay(key, method, tenant)
            await self._send_stored(send, key, cached_after, replay_count=count)
            _safe_inc(IDEMP_REPLAYS, {"method": method, "tenant": tenant})
            return

        # Last resort: run once without caching.
        status, resp_headers, resp_body, _ = await self._run_downstream(scope, body)
        await self._send_fresh(send, status, resp_headers, resp_body)

    # ------------------------- helpers -------------------------

    async def _read_body(self, receive: Receive) -> bytes:
        chunks: list[bytes] = []
        more_body = True
        while more_body:
            msg = await receive()
            if msg.get("type") != "http.request":
                continue
            b = msg.get("body") or b""
            if b:
                chunks.append(b)
            more_body = bool(msg.get("more_body"))
        return b"".join(chunks)

    async def _wait_for_release_or_value(self, key: str, timeout: float) -> str:
        """
        Poll with backoff + jitter until either a cached value appears OR
        the lock disappears. Returns "value", "released", or "timeout".
        """
        deadline = time.time() + timeout
        delay = 0.01
        steps = 0
        while time.time() < deadline:
            try:
                if await self.store.get(key):
                    _safe_inc(IDEMP_BACKOFF_STEPS)
                    return "value"
            except Exception:
                _safe_inc(IDEMP_ERRORS, {"phase": "get"})
            try:
                meta = await self.store.meta(key)
                if not meta.get("lock") or meta.get("state") != "in_progress":
                    _safe_inc(IDEMP_BACKOFF_STEPS)
                    return "released"
            except Exception:
                _safe_inc(IDEMP_ERRORS, {"phase": "meta"})
            jitter = random.random() * min(delay, 0.05)
            await asyncio.sleep(delay + jitter)
            delay = min(delay * 2.0, 0.2)
            steps += 1
        if steps:
            _safe_inc(IDEMP_BACKOFF_STEPS)
        return "timeout"

    async def _on_replay(self, key: str, method: str, tenant: str) -> int:
        """
        Handle replay bookkeeping:
        - bump replay counter and record histogram value
        - refresh TTL/recency via store.touch(...)
        Returns the new replay count (0 if unavailable).
        """
        try:
            new_count_opt = await self.store.bump_replay(key)
            new_count = int(new_count_opt or 0)
            _safe_observe(
                IDEMP_REPLAY_COUNT_HIST,
                float(new_count),
                {"method": method, "tenant": tenant},
            )

            if self.touch_on_replay:
                touch_fn = getattr(self.store, "touch", None)
                if callable(touch_fn):
                    # Support both touch(key, ttl) and touch(key) signatures.
                    try:
                        await touch_fn(key, self.ttl_s) 
                    except TypeError:
                        await touch_fn(key)  
                # We rely on the store's touch implementation to:
                #   - move the key in recency
                #   - refresh TTL for value/state
                #   - increment guardrail_idemp_touches_total

            return new_count
        except Exception:
            _safe_inc(IDEMP_ERRORS)
            return 0

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
        *,
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
                more = bool(message.get("more_body"))
                if more:
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

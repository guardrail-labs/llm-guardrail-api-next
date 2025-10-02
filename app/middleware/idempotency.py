"""Idempotency middleware with safe metrics usage and robust follower retry."""
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
    IDEMP_MISSES,
    IDEMP_REPLAYS,
    IDEMP_REPLAY_COUNT_HIST,
    IDEMP_TOUCHES,
    metric_counter,
)

# Local, unlabeled counter (always safe)
IDEMP_BACKOFF_STEPS = metric_counter(
    "guardrail_idemp_backoff_steps_total",
    "Backoff steps taken by followers",
)


# ---------------------------
# Helpers: safe metric calls
# ---------------------------

def _safe_inc(metric: Any, labels: Optional[Mapping[str, str]] = None) -> None:
    """Increment a counter, tolerating label schema mismatches."""
    try:
        if labels:
            metric.labels(**labels).inc()
        else:
            metric.inc()
    except Exception:
        # Retry unlabeled; if that fails, swallow
        try:
            metric.inc()
        except Exception:
            pass


def _safe_observe(histogram: Any, value: float, labels: Optional[Mapping[str, str]] = None) -> None:
    """Observe a histogram value, tolerating label schema mismatches."""
    try:
        if labels:
            histogram.labels(**labels).observe(value)
        else:
            histogram.observe(value)
    except Exception:
        # Retry unlabeled; if that fails, swallow
        try:
            histogram.observe(value)
        except Exception:
            pass


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

        # Decide interception BEFORE consuming the body to preserve streaming for pass-through.
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        key = headers.get("x-idempotency-key")

        if not key:
            # No key -> no interception; preserve streaming
            await self.app(scope, receive, send)
            return

        if not _valid_key(key):
            # Key is present but invalid -> reject (400), do NOT pass-through
            await self._send_invalid_key(send)
            return

        # Read body once (bounded later when deciding whether to cache).
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
            _safe_inc(IDEMP_ERRORS)  # phase label may not exist; keep unlabeled
            cached = None

        if cached:
            _safe_inc(IDEMP_HITS, {"method": method, "tenant": tenant})
            new_count = await _safe_bump_replay(self.store, key, method, tenant)
            if self.touch_on_replay:
                _safe_inc(IDEMP_TOUCHES, {"tenant": tenant})
            await self._send_stored(send, key, cached, replay_count=new_count)
            _safe_inc(IDEMP_REPLAYS, {"method": method, "tenant": tenant})
            return

        _safe_inc(IDEMP_MISSES, {"method": method, "tenant": tenant})

        # Attempt to become the leader
        try:
            ok, owner = await self.store.acquire_leader(key, self.ttl_s, body_fp)
        except Exception:
            _safe_inc(IDEMP_ERRORS)
            ok, owner = False, None

        if ok:
            await self._handle_leader(scope, body, key, body_fp, tenant, method, owner, send)
            return

        # Follower path: loop until value appears OR we acquire leadership, bounded by TTL.
        deadline = time.time() + float(self.ttl_s)
        delay = 0.01
        while time.time() < deadline:
            # 1) Value available? (leader finished with a cacheable response)
            try:
                cached_after = await self.store.get(key)
            except Exception:
                _safe_inc(IDEMP_ERRORS)
                cached_after = None

            if cached_after:
                _safe_inc(IDEMP_HITS, {"method": method, "tenant": tenant})
                new_count = await _safe_bump_replay(self.store, key, method, tenant)
                if self.touch_on_replay:
                    _safe_inc(IDEMP_TOUCHES, {"tenant": tenant})
                await self._send_stored(send, key, cached_after, replay_count=new_count)
                _safe_inc(IDEMP_REPLAYS, {"method": method, "tenant": tenant})
                return

            # 2) Try to acquire leadership and run fresh
            try:
                ok2, owner2 = await self.store.acquire_leader(key, self.ttl_s, body_fp)
            except Exception:
                _safe_inc(IDEMP_ERRORS)
                ok2, owner2 = False, None

            if ok2:
                await self._handle_leader(scope, body, key, body_fp, tenant, method, owner2, send)
                return

            IDEMP_BACKOFF_STEPS.inc()
            jitter = random.random() * min(delay, 0.05)
            await asyncio.sleep(delay + jitter)
            delay = min(delay * 2.0, 0.2)

        # TTL expired: run once without caching (best effort).
        status, resp_headers, resp_body, _ = await self._run_downstream(scope, body)
        await self._send_fresh(send, status, resp_headers, resp_body)

    async def _handle_leader(
        self,
        scope: Scope,
        body: bytes,
        key: str,
        body_fp: str,
        tenant: str,
        method: str,
        owner: Optional[str],
        send: Send,
    ) -> None:
        try:
            status, resp_headers, resp_body, is_streaming = await self._run_downstream(scope, body)
        except Exception:
            try:
                await self.store.release(key, owner=owner)
            except Exception:
                _safe_inc(IDEMP_ERRORS)
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
                _safe_inc(IDEMP_ERRORS)
            finally:
                try:
                    await self.store.release(key, owner=owner)
                except Exception:
                    _safe_inc(IDEMP_ERRORS)
        else:
            # Not cacheable (e.g., 5xx) -> just release lock; followers will later acquire and run.
            try:
                await self.store.release(key, owner=owner)
            except Exception:
                _safe_inc(IDEMP_ERRORS)

        await self._send_fresh(send, status, resp_headers, resp_body)

    async def _send_invalid_key(self, send: Send) -> None:
        """Send exactly the error body the tests expect."""
        body = b"invalid idempotency key"
        headers = [
            (b"content-type", b"text/plain; charset=utf-8"),
            (b"content-length", str(len(body)).encode()),
        ]
        await send({"type": "http.response.start", "status": 400, "headers": headers})
        await send({"type": "http.response.body", "body": body})

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


async def _safe_bump_replay(
    store: IdemStore, key: str, method: str, tenant: str
) -> int:
    """Bump replay count safely and record histogram; never raise."""
    try:
        new_count_opt = await store.bump_replay(key)
        new_count = int(new_count_opt or 0)
        _safe_observe(IDEMP_REPLAY_COUNT_HIST, float(new_count), {"method": method, "tenant": tenant})
        return new_count
    except Exception:
        _safe_inc(IDEMP_ERRORS)
        return 0

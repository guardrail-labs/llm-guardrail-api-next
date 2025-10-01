"""Idempotency middleware with optional header, owner tokens, and follower backoff."""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import random
import time
from typing import Any, Callable, Iterable, Mapping, MutableMapping, Optional, Tuple

from starlette.types import ASGIApp, Receive, Scope, Send

from app.idempotency.store import IdemStore, StoredResponse
from app.idempotency.utils import mask_idempotency_key
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


def _env_touch_on_replay() -> bool:
    return os.environ.get("IDEMP_TOUCH_ON_REPLAY", "0").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


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
    ) -> None:
        self.app = app
        self.store = store
        self.ttl_s = int(ttl_s) if ttl_s is not None else _env_ttl()
        self.methods = tuple(m.upper() for m in (methods or _env_methods()))
        self.max_body = int(max_body) if max_body is not None else _env_max_body()
        self.cache_streaming = cache_streaming
        self.tenant_provider = tenant_provider or (lambda scope: "default")
        self.touch_on_replay = (
            bool(touch_on_replay)
            if touch_on_replay is not None
            else _env_touch_on_replay()
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Not a managed method? Just pass through (streaming preserved).
        if scope["type"] != "http" or scope["method"].upper() not in self.methods:
            await self.app(scope, receive, send)
            return

        method = scope["method"].upper()
        tenant = self.tenant_provider(scope)

        # Read headers BEFORE touching the body so we can preserve streaming
        # when there is no idempotency header.
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        key = headers.get("x-idempotency-key")
        if not key:
            # No idempotency => fully delegate (no buffering).
            await self.app(scope, receive, send)
            return
        if not _valid_key(key):
            await self._send_error(send, 400, "invalid idempotency key")
            return

        # Drain request body once (we only do this when key is present).
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

        # Fast path: if we already have a matching cached body, replay.
        try:
            cached = await self.store.get(key)
        except Exception:
            IDEMP_ERRORS.labels(phase="get").inc()
            cached = None

        if cached and cached.body_sha256 == body_fp:
            IDEMP_HITS.labels(method=method, tenant=tenant, role="follower").inc()
            await self._send_stored(send, key, cached, method, tenant)
            IDEMP_REPLAYS.labels(method=method, tenant=tenant, role="follower").inc()
            return

        miss_role: Optional[str] = None

        # Try to become leader.
        try:
            ok, owner = await self.store.acquire_leader(key, self.ttl_s, body_fp)
        except Exception:
            IDEMP_ERRORS.labels(phase="acquire").inc()
            ok, owner = False, None

        miss_role = "leader" if ok else "follower"
        IDEMP_MISSES.labels(method=method, tenant=tenant, role=miss_role).inc()

        if ok:
            _log_event(
                "idemp_leader_acquired",
                key=key,
                tenant=tenant,
                role="leader",
                state="in_progress",
                replay_count=None,
                fp_prefix=_fp_prefix(body_fp),
            )
            IDEMP_IN_PROGRESS.labels(tenant=tenant, role="leader").inc()
            await self._leader_execute_and_persist(key, owner, scope, body, send)
            return

        # Follower path — detect payload conflict.
        conflict = False
        try:
            meta = await self.store.meta(key)
        except Exception:
            IDEMP_ERRORS.labels(phase="meta").inc()
            meta = {}
        else:
            fp = meta.get("payload_fingerprint") if isinstance(meta, dict) else None
            if fp and fp != body_fp:
                conflict = True
                IDEMP_CONFLICTS.labels(method=method, tenant=tenant, role="follower").inc()
                _log_event(
                    "idemp_conflict",
                    key=key,
                    tenant=tenant,
                    role="follower",
                    state="conflict",
                    replay_count=None,
                    fp_prefix=_fp_prefix(body_fp),
                )

        # If we saw a conflict, do NOT ever replay the old cached value.
        # Try to acquire immediately; if not, wait for release (ignore values),
        # then acquire and execute fresh.
        if conflict:
            try:
                ok2, owner2 = await self.store.acquire_leader(key, self.ttl_s, body_fp)
            except Exception:
                IDEMP_ERRORS.labels(phase="acquire").inc()
                ok2, owner2 = False, None

            if not ok2:
                await self._wait_for_release_or_value(key, timeout=self.ttl_s)
                try:
                    ok2, owner2 = await self.store.acquire_leader(
                        key, self.ttl_s, body_fp
                    )
                except Exception:
                    IDEMP_ERRORS.labels(phase="acquire").inc()
                    ok2, owner2 = False, None

            if ok2:
                IDEMP_IN_PROGRESS.labels(tenant=tenant, role="leader").inc()
                _log_event(
                    "idemp_leader_acquired",
                    key=key,
                    tenant=tenant,
                    role="leader",
                    state="in_progress",
                    replay_count=None,
                    fp_prefix=_fp_prefix(body_fp),
                )
                await self._leader_execute_and_persist(key, owner2, scope, body, send)
                return

            # Last resort: run once without caching (do not replay).
            status, resp_headers, resp_body, _ = await self._run_downstream(scope, body)
            await self._send_fresh(send, status, resp_headers, resp_body)
            return

        # No conflict: normal follower wait, then replay if value appears.
        start = time.time()
        wait_result = await self._wait_for_release_or_value(key, timeout=self.ttl_s)
        waited = max(time.time() - start, 0.0)
        IDEMP_LOCK_WAIT.observe(waited)
        _log_event(
            "idemp_follower_wait_complete",
            key=key,
            tenant=tenant,
            role="follower",
            state=wait_result,
            replay_count=None,
            fp_prefix=_fp_prefix(body_fp),
            wait_ms=waited * 1000.0,
        )

        try:
            cached_after = await self.store.get(key)
        except Exception:
            IDEMP_ERRORS.labels(phase="get").inc()
            cached_after = None

        if cached_after and cached_after.body_sha256 == body_fp:
            IDEMP_HITS.labels(method=method, tenant=tenant, role="follower").inc()
            await self._send_stored(send, key, cached_after, method, tenant)
            IDEMP_REPLAYS.labels(method=method, tenant=tenant, role="follower").inc()
            return

        # Try to become leader now; else run fresh (no cache).
        try:
            ok2, owner2 = await self.store.acquire_leader(key, self.ttl_s, body_fp)
        except Exception:
            IDEMP_ERRORS.labels(phase="acquire").inc()
            ok2, owner2 = False, None

        if miss_role is None:
            miss_role = "leader" if ok2 else "follower"
            IDEMP_MISSES.labels(method=method, tenant=tenant, role=miss_role).inc()

        if ok2:
            IDEMP_IN_PROGRESS.labels(tenant=tenant, role="leader").inc()
            _log_event(
                "idemp_leader_acquired",
                key=key,
                tenant=tenant,
                role="leader",
                state="in_progress",
                replay_count=None,
                fp_prefix=_fp_prefix(body_fp),
            )
            await self._leader_execute_and_persist(key, owner2, scope, body, send)
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
    ) -> None:
        """Run downstream as leader, decide caching, always release lock."""
        try:
            status, resp_headers, resp_body, is_streaming = await self._run_downstream(
                scope, body
            )
        except Exception:
            # Ensure followers can proceed, then emit a 500.
            try:
                await self.store.release(key, owner=owner)
            except Exception:
                IDEMP_ERRORS.labels(phase="release").inc()
            await self._send_500(send)
            return

        cacheable = status < 500 and (not is_streaming or self.cache_streaming)
        too_large = len(resp_body) > self.max_body

        if not cacheable or too_large:
            if is_streaming and not self.cache_streaming:
                IDEMP_STREAMING_SKIPPED.inc()
            if too_large:
                IDEMP_BODY_TOO_LARGE.inc()
            try:
                await self.store.release(key, owner=owner)
            except Exception:
                IDEMP_ERRORS.labels(phase="release").inc()
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
            IDEMP_ERRORS.labels(phase="put").inc()
        finally:
            try:
                await self.store.release(key, owner=owner)
            except Exception:
                IDEMP_ERRORS.labels(phase="release").inc()

        await self._send_fresh(send, status, resp_headers, resp_body)

    async def _wait_for_release_or_value(self, key: str, timeout: float) -> str:
        """
        Poll with backoff + jitter until either a value appears OR the lock
        disappears / state changes. Returns "value", "released", or "timeout".
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
        # Ensure replay header is explicitly false.
        hdrs = [(k.encode(), v.encode()) for k, v in headers.items()]
        hdrs.append((b"idempotency-replayed", b"false"))
        hdrs.append((b"content-length", str(len(body)).encode()))
        await send({"type": "http.response.start", "status": status, "headers": hdrs})
        await send({"type": "http.response.body", "body": body})

    async def _send_stored(
        self, send: Send, key: str, resp: StoredResponse, method: str, tenant: str
    ) -> None:
        hdrs = [(k.encode(), v.encode()) for k, v in resp.headers.items()]
        hdrs.append((b"idempotency-replayed", b"true"))
        hdrs.append((b"x-idempotency-key", key.encode()))
        touch_ttl = self.ttl_s if self.touch_on_replay else None
        replay_count: int | None
        try:
            replay_count = await self.store.bump_replay(key, touch_ttl_s=touch_ttl)
        except Exception:
            IDEMP_ERRORS.labels(phase="bump_replay").inc()
            replay_count = None
        else:
            if replay_count is not None:
                resp.replay_count = replay_count
                IDEMP_REPLAY_COUNT_HIST.labels(tenant=tenant, method=method).observe(
                    float(replay_count)
                )
                if self.touch_on_replay and touch_ttl is not None:
                    IDEMP_TOUCHES.labels(tenant=tenant, role="follower").inc()

        count_header: str | None = None
        if replay_count is not None:
            count_header = str(replay_count)
        elif resp.replay_count:
            count_header = str(resp.replay_count)
        if count_header is not None:
            hdrs.append((b"idempotency-replay-count", count_header.encode()))
        body = resp.body
        hdrs.append((b"content-length", str(len(body)).encode()))
        final_replay = replay_count if replay_count is not None else resp.replay_count
        _log_event(
            "idemp_replay",
            key=key,
            tenant=tenant,
            role="follower",
            state="stored",
            replay_count=int(final_replay) if final_replay is not None else None,
            fp_prefix=_fp_prefix(resp.body_sha256),
        )
        await send({"type": "http.response.start", "status": resp.status, "headers": hdrs})
        await send({"type": "http.response.body", "body": body})

    async def _run_downstream(
        self,
        scope: Scope,
        body: bytes,
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
_log = logging.getLogger("guardrail.idempotency")


def _fp_prefix(fp: Optional[str]) -> Optional[str]:
    if not fp:
        return None
    return str(fp)[:8]


def _log_event(
    event: str,
    *,
    key: str,
    tenant: str,
    role: str,
    state: str,
    replay_count: Optional[int],
    fp_prefix: Optional[str],
    wait_ms: float = 0.0,
) -> None:
    try:
        _log.info(
            event,
            extra={
                "idempotency_key": mask_idempotency_key(key),
                "tenant": tenant,
                "role": role,
                "state": state,
                "replay_count": replay_count,
                "fp_prefix": fp_prefix,
                "wait_ms": round(wait_ms, 3),
            },
        )
    except Exception:
        # Logging should never block request handling.
        pass

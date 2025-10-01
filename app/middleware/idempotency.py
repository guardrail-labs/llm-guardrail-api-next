"""Idempotency middleware with env defaults, owner tokens, and follower backoff."""
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
from app.metrics import (  # Prometheus helpers and counters
    IDEMP_CONFLICTS,
    IDEMP_ERRORS,
    IDEMP_HITS,
    IDEMP_IN_PROGRESS,
    IDEMP_LOCK_WAIT,
    IDEMP_MISSES,
    IDEMP_REPLAYS,
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
    ) -> None:
        self.app = app
        self.store = store
        self.ttl_s = int(ttl_s) if ttl_s is not None else _env_ttl()
        self.methods = tuple(m.upper() for m in (methods or _env_methods()))
        self.max_body = int(max_body) if max_body is not None else _env_max_body()
        self.cache_streaming = cache_streaming
        self.tenant_provider = tenant_provider or (lambda scope: "default")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"].upper() not in self.methods:
            await self.app(scope, receive, send)
            return

        method = scope["method"].upper()
        tenant = self.tenant_provider(scope)

        # Read the full body once (bounded by max_body for caching decision)
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

        # Header is optional: if absent, bypass idempotency and forward as-is.
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        key = headers.get("x-idempotency-key")
        if key is None:
            status, resp_headers, resp_body, _ = await self._run_downstream(scope, body)
            await self._send_direct(send, status, resp_headers, resp_body)
            return

        # If a key is supplied, validate it.
        if not _valid_key(key):
            await self._send_error(send, 400, "invalid idempotency key")
            return

        # Fingerprint the payload for conflict detection & cache coherence.
        body_fp = hashlib.sha256(body).hexdigest()

        # Fast path: try to read a stored response first.
        try:
            cached = await self.store.get(key)
        except Exception:
            IDEMP_ERRORS.labels(phase="get").inc()
            cached = None

        # Respect "same key + different body => treat as fresh (overwrite)".
        if cached and cached.body_sha256 and cached.body_sha256 != body_fp:
            cached = None

        if cached:
            IDEMP_HITS.labels(method=method, tenant=tenant).inc()
            await self._send_stored(send, key, cached)
            IDEMP_REPLAYS.labels(method=method, tenant=tenant).inc()
            return

        IDEMP_MISSES.labels(method=method, tenant=tenant).inc()

        # Attempt to become leader.
        try:
            ok, owner = await self.store.acquire_leader(key, self.ttl_s, body_fp)
        except Exception:
            IDEMP_ERRORS.labels(phase="acquire").inc()
            ok, owner = False, None

        if ok:
            IDEMP_IN_PROGRESS.labels(tenant=tenant).inc()
            # Leader path: run downstream
            try:
                status, resp_headers, resp_body, is_streaming = await self._run_downstream(
                    scope,
                    body,
                )
            except Exception:
                # Downstream raised -> ensure followers can proceed
                try:
                    await self.store.release(key, owner=owner)
                except Exception:
                    IDEMP_ERRORS.labels(phase="release").inc()
                raise

            # Cache decision:
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
                # Non-cacheable outcome (streaming, 5xx, or too large) — always release.
                try:
                    await self.store.release(key, owner=owner)
                except Exception:
                    IDEMP_ERRORS.labels(phase="release").inc()

            # Emit the fresh response (mark replayed=false)
            await self._send_fresh(send, status, resp_headers, resp_body)
            return

        # Follower path: observe potential conflict and wait with backoff.
        try:
            meta = await self.store.meta(key)
        except Exception:
            IDEMP_ERRORS.labels(phase="meta").inc()
            meta = {}
        else:
            fp = meta.get("payload_fingerprint") if isinstance(meta, dict) else None
            if fp and fp != body_fp:
                IDEMP_CONFLICTS.labels(method=method, tenant=tenant).inc()

        start = time.time()
        await self._wait_for_release_or_value(key, timeout=self.ttl_s)
        IDEMP_LOCK_WAIT.observe(max(time.time() - start, 0.0))

        try:
            cached_after = await self.store.get(key)
        except Exception:
            IDEMP_ERRORS.labels(phase="get").inc()
            cached_after = None

        # Again, respect body mismatch rule after wait.
        if cached_after and cached_after.body_sha256 and cached_after.body_sha256 != body_fp:
            cached_after = None

        if cached_after:
            IDEMP_HITS.labels(method=method, tenant=tenant).inc()
            await self._send_stored(send, key, cached_after)
            IDEMP_REPLAYS.labels(method=method, tenant=tenant).inc()
            return

        # Lock cleared or timeout without a value -> try to become leader again.
        try:
            ok2, owner2 = await self.store.acquire_leader(key, self.ttl_s, body_fp)
        except Exception:
            IDEMP_ERRORS.labels(phase="acquire").inc()
            ok2, owner2 = False, None

        if ok2:
            IDEMP_IN_PROGRESS.labels(tenant=tenant).inc()
            try:
                status, resp_headers, resp_body, is_streaming = await self._run_downstream(
                    scope,
                    body,
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

        # As a last resort if we somehow couldn't acquire: just run once (no cache).
        status, resp_headers, resp_body, _ = await self._run_downstream(scope, body)
        await self._send_fresh(send, status, resp_headers, resp_body)

    async def _wait_for_release_or_value(self, key: str, timeout: float) -> str:
        """
        Poll with backoff

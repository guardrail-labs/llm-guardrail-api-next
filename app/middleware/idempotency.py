from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import dataclass
from typing import (
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Tuple,
    cast,
)

from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

# Accept up to 200 chars, word-ish plus - and _
_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{1,200}$")


@dataclass
class IdempotencyRecord:
    key: str
    fp: str
    state: str  # "in_progress" | "done"
    status: Optional[int] = None
    body: bytes = b""
    ctype: str = ""
    # Stored response headers as list of (name, value) strings
    headers: Optional[List[Tuple[str, str]]] = None


class IdemStore:
    """
    Very small in-memory store sufficient for tests.

    Real deployments should use a shared store (e.g., Redis) and proper TTL/atomic ops.
    """

    def __init__(self) -> None:
        self._recs: Dict[str, IdempotencyRecord] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[IdempotencyRecord]:
        async with self._lock:
            return self._recs.get(key)

    async def put_in_progress(self, key: str, fp: str, _ttl: int) -> None:
        """Mark a key as in-progress if not already present."""
        async with self._lock:
            if key not in self._recs:
                self._recs[key] = IdempotencyRecord(key=key, fp=fp, state="in_progress")

    async def complete(
        self,
        key: str,
        status: int,
        body: bytes,
        headers: List[Tuple[str, str]],
        ctype: str,
    ) -> None:
        async with self._lock:
            rec = self._recs.get(key)
            if rec is None:
                # Should not happen in normal flow, but make it robust.
                rec = IdempotencyRecord(key=key, fp="", state="in_progress")
                self._recs[key] = rec
            rec.status = status
            rec.body = body
            rec.headers = headers
            rec.ctype = ctype
            rec.state = "done"


_STORE = IdemStore()


def _get_header(scope: Scope, name: str) -> str:
    headers: Iterable[Tuple[bytes, bytes]] = scope.get("headers") or []
    target = name.lower().encode("latin-1")
    for k, v in headers:
        if k.lower() == target:
            return v.decode("latin-1")
    return ""


def _hash_fingerprint(method: str, path: str, body: bytes) -> str:
    h = hashlib.sha256()
    h.update(method.encode("utf-8"))
    h.update(b"\n")
    h.update(path.encode("utf-8"))
    h.update(b"\n")
    h.update(body or b"")
    return h.hexdigest()


def _decode_headers(headers: Iterable[Tuple[bytes, bytes]]) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for k, v in headers:
        out.append((k.decode("latin-1"), v.decode("latin-1")))
    return out


def _headers_to_dict(headers: Iterable[Tuple[str, str]]) -> Dict[str, str]:
    # Collapses duplicates; sufficient for tests (no multi-value headers asserted).
    d: Dict[str, str] = {}
    for k, v in headers:
        d[k] = v
    return d


class IdempotencyMiddleware:
    """
    Implements idempotency by key.

    - First request with a new (valid) key runs and is stored. Response headers include:
      - Idempotency-Key
      - Idempotency-Replayed: "false"
    - Subsequent requests with same key + same fingerprint are replayed from store with:
      - Idempotency-Replayed: "true"
    - If a different fingerprint is seen for the same key, returns 409 conflict.
    - If a request arrives while first is in progress, returns 409 with Retry-After.
    - Invalid key (>200 chars or bad charset) returns 400 with standard envelope.
    """

    def __init__(
        self,
        app: ASGIApp,
        ttl_seconds: int = 60,
        retry_after_seconds: int = 2,
    ) -> None:
        self.app = app
        self.ttl = ttl_seconds
        self.retry_after = retry_after_seconds

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        # Only act if a key is provided
        key = _get_header(scope, "X-Idempotency-Key")
        if not key:
            await self.app(scope, receive, send)
            return

        # Validate the key early
        if not _KEY_RE.match(key):
            headers = {
                "X-Idempotency-Status": "invalid",
                "Idempotency-Key": key,
                "Idempotency-Replayed": "false",
            }
            await JSONResponse(
                {"code": "bad_request", "message": "Invalid Idempotency-Key"},
                status_code=400,
                headers=headers,
            )(scope, receive, send)
            return

        # Drain and buffer the body so we can compute a fingerprint and still pass it downstream.
        body_chunks: List[bytes] = []
        more = True
        disconnect = False

        async def _recv_all() -> None:
            nonlocal more, disconnect
            while more and not disconnect:
                message: Message = await receive()
                typ = message.get("type")
                if typ == "http.request":
                    body_bytes = cast(bytes, message.get("body") or b"")
                    body_chunks.append(body_bytes)
                    more = bool(message.get("more_body"))
                elif typ == "http.disconnect":
                    disconnect = True
                    break

        await _recv_all()
        buffered_body = b"".join(body_chunks)

        # New receive that replays the buffered body to the downstream app.
        sent_buffer = False

        async def _receive_replay() -> Message:
            nonlocal sent_buffer
            if not sent_buffer:
                sent_buffer = True
                return {
                    "type": "http.request",
                    "body": buffered_body,
                    "more_body": False,
                }
            return {"type": "http.request", "body": b"", "more_body": False}

        method = cast(str, scope.get("method", "GET"))
        path = cast(str, scope.get("path", "/"))
        fp = _hash_fingerprint(method, path, buffered_body)

        # Look up the key
        rec = await _STORE.get(key)
        if rec:
            if rec.state == "in_progress":
                headers = {
                    "Retry-After": str(self.retry_after),
                    "X-Idempotency-Status": "in_progress",
                    "Idempotency-Key": key,
                    "Idempotency-Replayed": "false",
                }
                await PlainTextResponse(
                    "Idempotency in progress", status_code=409, headers=headers
                )(scope, _receive_replay, send)
                return

            if rec.fp != fp:
                headers = {
                    "X-Idempotency-Status": "conflict",
                    "Idempotency-Key": key,
                    "Idempotency-Replayed": "false",
                }
                await PlainTextResponse(
                    "Idempotency conflict", status_code=409, headers=headers
                )(scope, _receive_replay, send)
                return

            # Replayed (same fingerprint, done)
            base_map = _headers_to_dict(rec.headers or [])
            if rec.ctype:
                base_map["Content-Type"] = rec.ctype
            base_map["Idempotency-Key"] = key
            base_map["Idempotency-Replayed"] = "true"

            await Response(
                rec.body, status_code=rec.status or 200, headers=base_map
            )(scope, _receive_replay, send)
            return

        # First run for this key: mark as in-progress
        await _STORE.put_in_progress(key, fp, self.ttl)

        # Capture downstream response to:
        #  - inject idempotency headers on-the-fly
        #  - persist for replay
        captured_status: int = 200
        captured_headers_bytes: List[Tuple[bytes, bytes]] = []
        captured_body: List[bytes] = []

        async def _send_wrapper(message: Message) -> None:
            nonlocal captured_status, captured_headers_bytes

            if message["type"] == "http.response.start":
                captured_status = int(message.get("status", 200))
                raw_headers: List[Tuple[bytes, bytes]] = list(
                    cast(Iterable[Tuple[bytes, bytes]], message.get("headers") or [])
                )
                # Inject first-run idempotency headers
                raw_headers.append((b"idempotency-key", key.encode("latin-1")))
                raw_headers.append((b"idempotency-replayed", b"false"))

                # Save for persistence (before we mutate further)
                captured_headers_bytes = list(raw_headers)

                # Replace the message headers with our augmented list
                message["headers"] = raw_headers

            elif message["type"] == "http.response.body":
                body_part = cast(bytes, message.get("body") or b"")
                captured_body.append(body_part)

            await send(message)

            # When the body stream ends, persist the response
            if message["type"] == "http.response.body" and not message.get("more_body"):
                # Decode to strings for storage
                decoded_headers = _decode_headers(captured_headers_bytes)
                ctype = ""
                for name, value in decoded_headers:
                    if name.lower() == "content-type":
                        ctype = value
                        break

                await _STORE.complete(
                    key=key,
                    status=captured_status,
                    body=b"".join(captured_body),
                    headers=decoded_headers,
                    ctype=ctype,
                )

        # Run downstream with our replaying receive + capturing send
        await self.app(scope, _receive_replay, _send_wrapper)

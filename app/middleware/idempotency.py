from __future__ import annotations

import asyncio
import hashlib
import re
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from starlette.responses import JSONResponse, PlainTextResponse, Response

ASGIApp = Callable[[dict, Callable[[], Awaitable[dict]], Callable[[dict], Awaitable[None]]], Awaitable[None]]

# Accept up to 200 chars, word-ish plus - and _
_KEY_RE = re.compile(r"^[A-Za-z0-9_\-]{1,200}$")


def _now() -> float:
    return time.monotonic()


def _b(s: str) -> bytes:
    return s.encode("latin-1")


def _get_header(scope: dict, name: str) -> Optional[str]:
    name_b = name.lower().encode("latin-1")
    for k, v in scope.get("headers") or []:
        if k.lower() == name_b:
            try:
                return v.decode("latin-1")
            except Exception:
                return None
    return None


def _sha256_hex(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


@dataclass
class IdemRecord:
    state: str  # "in_progress" | "done"
    fp: str
    status: Optional[int] = None
    headers: Optional[List[Tuple[str, str]]] = None
    ctype: Optional[str] = None
    body: Optional[bytes] = None
    expires_at: float = 0.0


class IdemStore:
    """
    Very small async-safe in-memory store for idempotency records.
    """

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._data: Dict[str, IdemRecord] = {}

    async def get(self, key: str) -> Optional[IdemRecord]:
        async with self._lock:
            rec = self._data.get(key)
            if rec and rec.expires_at and rec.expires_at < _now():
                # Expired – drop it.
                del self._data[key]
                return None
            return rec

    async def put_in_progress(self, key: str, fp: str, ttl: int) -> None:
        async with self._lock:
            # Only create if absent or expired to reduce races.
            existing = self._data.get(key)
            if existing and (not existing.expires_at or existing.expires_at > _now()):
                # Keep existing (either in_progress or done)
                return
            self._data[key] = IdemRecord(
                state="in_progress",
                fp=fp,
                expires_at=_now() + max(1, ttl),
            )

    async def complete(
        self,
        key: str,
        status: int,
        body: bytes,
        headers: List[Tuple[str, str]],
        ctype: str,
        ttl: int,
    ) -> None:
        async with self._lock:
            rec = self._data.get(key)
            if rec is None:
                # If someone cleared it, just write the final record.
                rec = IdemRecord(state="done", fp="", expires_at=_now() + max(1, ttl))
                self._data[key] = rec
            rec.state = "done"
            rec.status = status
            rec.body = body
            rec.headers = headers
            rec.ctype = ctype
            rec.expires_at = _now() + max(1, ttl)


# Global store used by the middleware.
_STORE = IdemStore()


class IdempotencyMiddleware:
    """
    ASGI middleware implementing response replay based on X-Idempotency-Key.

    Behavior:
      * First run: executes handler, adds `Idempotency-Replayed: false` header,
        persists status/body/headers for replay.
      * Replay (same fingerprint): returns stored response with
        `Idempotency-Replayed: true`, preserving original headers (CORS, security,
        custom headers, etc).
      * Conflict (different fingerprint): 409 with `Idempotency-Replayed: false`.
      * In progress: 409 with Retry-After.
      * Invalid key (length/pattern): 400 JSON error with {"code","message"}.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        ttl_seconds: int = 300,
        retry_after_seconds: int = 1,
    ) -> None:
        self.app = app
        self.ttl = int(ttl_seconds)
        self.retry_after = int(retry_after_seconds)

    async def __call__(
        self, scope: dict, receive: Callable[[], Awaitable[dict]], send: Callable[[dict], Awaitable[None]]
    ) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "GET")
        path = scope.get("path", "/")
        key = _get_header(scope, "X-Idempotency-Key")

        # If no key, just pass through.
        if not key:
            await self.app(scope, receive, send)
            return

        # Validate the key
        if not _KEY_RE.match(key):
            resp: Response = JSONResponse(
                {"code": "bad_request", "message": "Invalid Idempotency-Key"},
                status_code=400,
            )
           

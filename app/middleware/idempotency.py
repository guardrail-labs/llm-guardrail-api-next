from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import dataclass
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    MutableMapping,
    Optional,
    Tuple,
)

from starlette.responses import JSONResponse, PlainTextResponse, Response

# ----- ASGI typing aliases (mypy-friendly) -----------------------------------

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

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

    async def reset_in_progress(self, key: str, fp: str, _ttl: int) -> None:
        """Force a key into in-progress state (overwrites any existing record)."""
        async with self._lock:
            self._recs[key] = IdempotencyRecord(key=key, fp=fp, state="in_progress")

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._recs.pop(key, None)

    async def complete(
        self,
        key: str,
        status: int,
        body: bytes,
        headers: List[Tuple[str, str]],
        ctype: str,
    ) -> None:
        async with self._

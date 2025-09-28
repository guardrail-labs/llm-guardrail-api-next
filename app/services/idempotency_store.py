# app/services/idempotency_store.py
from __future__ import annotations

import asyncio
import hashlib
import time
from typing import Dict, List, Optional, Tuple


class IdemRecord:
    __slots__ = ("state", "status", "body", "ctype", "fp", "headers", "expires_at")

    def __init__(
        self,
        state: str,
        status: int = 0,
        body: bytes = b"",
        ctype: str = "",
        fp: str = "",
        headers: Optional[List[Tuple[str, str]]] = None,
        ttl: int = 0,
    ) -> None:
        self.state = state
        self.status = status
        self.body = body
        self.ctype = ctype
        self.fp = fp
        self.headers = headers or []
        self.expires_at = time.time() + ttl if ttl > 0 else 0.0

    def expired(self) -> bool:
        return bool(self.expires_at) and time.time() >= self.expires_at


class IdemStore:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._data: Dict[str, IdemRecord] = {}

    async def get(self, key: str) -> Optional[IdemRecord]:
        async with self._lock:
            rec = self._data.get(key)
            if rec and rec.expired():
                del self._data[key]
                return None
            return rec

    async def put_in_progress(self, key: str, fp: str, ttl: int) -> None:
        async with self._lock:
            self._data[key] = IdemRecord("in_progress", fp=fp, ttl=ttl)

    async def complete(
        self,
        key: str,
        status: int,
        body: bytes,
        headers: List[Tuple[str, str]] | None,
        ctype: str,
        fp: str,
        ttl: int,
    ) -> None:
        async with self._lock:
            # We persist status/body/ctype/fp/headers for faithful replay
            self._data[key] = IdemRecord(
                "done", status=status, body=body, ctype=ctype, fp=fp, headers=headers or [], ttl=ttl
            )

    async def clear(self, key: str) -> None:
        async with self._lock:
            self._data.pop(key, None)


def body_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


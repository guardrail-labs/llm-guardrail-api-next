"""Abstract interfaces and data models for idempotency storage."""
from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple
from abc import ABC, abstractmethod


@dataclass(frozen=True)
class StoredResponse:
    """Structured, serializable representation of a cached response."""

    status: int
    headers: Mapping[str, str]
    body: bytes
    content_type: Optional[str] = None
    stored_at: float = 0.0
    replay_count: int = 0
    body_sha256: str = ""

    def to_jsonable(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "headers": {str(k).lower(): str(v) for k, v in self.headers.items()},
            "body_b64": base64.b64encode(self.body).decode("ascii"),
            "content_type": self.content_type,
            "stored_at": self.stored_at,
            "replay_count": self.replay_count,
            "body_sha256": self.body_sha256,
        }


class IdemStore(ABC):
    """
    Contract a store must satisfy. Implementations must be concurrency-safe.

    Ownership: acquire_leader returns (ok, owner_token). If ok, the caller is the
    leader and must use `owner_token` when releasing the lock. Release SHOULD be
    owner-checked when owner_token is provided, but MUST fall back to best-effort
    unlock when owner_token is None (back-compat).
    """

    @abstractmethod
    async def acquire_leader(
        self, key: str, ttl_s: int, payload_fingerprint: str
    ) -> Tuple[bool, Optional[str]]:
        ...

    @abstractmethod
    async def get(self, key: str) -> Optional[StoredResponse]:
        ...

    @abstractmethod
    async def put(self, key: str, resp: StoredResponse, ttl_s: int) -> None:
        ...

    @abstractmethod
    async def release(self, key: str, owner: Optional[str] = None) -> bool:
        ...

    @abstractmethod
    async def meta(self, key: str) -> Mapping[str, Any]:
        ...

    @abstractmethod
    async def purge(self, key: str) -> bool:
        ...

    @abstractmethod
    async def list_recent(self, limit: int = 50) -> List[Tuple[str, float]]:
        ...

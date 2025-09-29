"""Abstract idempotency store primitives."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Mapping, Optional, Tuple


@dataclass
class StoredResponse:
    """Serialized HTTP response stored for idempotency replay."""

    status: int
    headers: Mapping[str, str]
    body: bytes
    content_type: Optional[str] = None
    stored_at: float = 0.0
    replay_count: int = 0
    body_sha256: str = ""


class IdemStore:
    """Interface for async idempotency stores."""

    async def acquire_leader(self, key: str, ttl_s: int, payload_fingerprint: str) -> bool:
        """Attempt to mark ``key`` as in-progress."""

    async def get(self, key: str) -> Optional[StoredResponse]:
        """Fetch a stored response for ``key`` if present."""

    async def put(self, key: str, resp: StoredResponse, ttl_s: int) -> None:
        """Persist the stored response for ``key`` with ``ttl_s`` seconds TTL."""

    async def release(self, key: str) -> None:
        """Release the in-progress lock for ``key`` without storing a response."""

    async def meta(self, key: str) -> Mapping[str, Any]:
        """Return metadata about ``key`` (lock state, stored status, etc.)."""

    async def purge(self, key: str) -> bool:
        """Remove any stored data for ``key`` and return ``True`` if something was deleted."""

    async def list_recent(self, limit: int = 50) -> List[Tuple[str, float]]:
        """Return most recently touched keys (key, timestamp)."""

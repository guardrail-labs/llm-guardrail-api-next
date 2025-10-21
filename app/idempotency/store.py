"""Idempotency store interface and value container."""

from __future__ import annotations

from dataclasses import dataclass
from typing import (
    Any,
    List,
    Mapping,
    Optional,
    Protocol,
    Tuple,
    runtime_checkable,
)


@dataclass
class StoredResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes
    content_type: Optional[str] = None
    stored_at: float = 0.0
    replay_count: int = 0
    body_sha256: str = ""


@runtime_checkable
class IdemStore(Protocol):
    async def acquire_leader(
        self,
        key: str,
        ttl_s: int,
        payload_fingerprint: str,
    ) -> Tuple[bool, Optional[str]]:
        ...

    async def get(self, key: str) -> Optional[StoredResponse]:
        ...

    async def put(self, key: str, resp: StoredResponse, ttl_s: int) -> None:
        ...

    async def release(self, key: str, owner: Optional[str] = None) -> bool:
        ...

    async def meta(self, key: str) -> Mapping[str, Any]:
        ...

    async def purge(self, key: str) -> bool:
        return False

    async def list_recent(self, limit: int = 50) -> List[Tuple[str, float]]:
        return []

    async def inspect(self, key: str) -> Mapping[str, Any]:
        raise NotImplementedError

    async def touch(self, key: str, ttl_s: int) -> bool:
        raise NotImplementedError

    async def bump_replay(self, key: str) -> int | None:
        """Increment replay count for ``key`` without mutating expirations."""
        ...


@dataclass(frozen=True)
class IdempotencyResult:
    """Finalized result retrieved by key. Payload is opaque bytes."""

    payload: bytes


@runtime_checkable
class IdempotencyStore(Protocol):
    async def begin(self, key: str, ttl_s: int, fingerprint: str) -> bool:
        """
        Reserve an idempotency key for processing.
        True  -> reservation created, caller may proceed.
        False -> key exists (either in flight or finalized).
        """

    async def get(self, key: str) -> Optional[IdempotencyResult]:
        """Return finalized result for key, or None if not available."""

    async def finalize(self, key: str, payload: bytes, ttl_s: int) -> None:
        """Store final payload with TTL, replacing any in-flight marker."""

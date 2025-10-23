from __future__ import annotations

from typing import Callable, Dict, Optional

from app.compliance import pii


class ComplianceRegistry:
    """Lightweight registry to warm compliance helpers."""

    def __init__(self) -> None:
        self._functions: Dict[str, Callable[..., object]] = {
            "hash_email": pii.hash_email,
            "hash_phone": pii.hash_phone,
            "redact_and_hash": pii.redact_and_hash,
        }

    def get(self, name: str) -> Optional[Callable[..., object]]:
        return self._functions.get(name)

from __future__ import annotations

from typing import Any, Protocol


class IngressRequest(Protocol):
    """Protocol for ingress requests consumed by middleware helpers."""

    text: str | None
    messages: list[Any] | None

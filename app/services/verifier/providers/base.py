from __future__ import annotations

from typing import Any, Dict, Optional, Protocol


class Provider(Protocol):
    """
    Provider protocol: implementors should be fast, deterministic, and
    return a dict in the standard shape below.
    """

    name: str

    async def assess(self, text: str, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Return shape:
            {
              "status": "safe" | "unsafe" | "ambiguous",
              "reason": str,
              "tokens_used": int
            }
        """
        ...


class ProviderRateLimited(Exception):
    """Provider indicated a rate/quotas limit."""

    def __init__(
        self, message: str = "rate_limited", retry_after_s: float | None = None
    ) -> None:
        super().__init__(message)
        self.retry_after_s = retry_after_s

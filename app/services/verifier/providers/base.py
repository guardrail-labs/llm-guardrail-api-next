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

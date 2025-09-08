from __future__ import annotations

import re
from typing import Any, Dict, Optional


class LocalRulesProvider:
    """
    Minimal heuristic provider so CI and local dev have a deterministic provider.
    - Unsafe if text matches obvious high-risk patterns.
    - Otherwise 'ambiguous' (lets policy/other providers decide).
    """

    name = "local_rules"

    _UNSAFE_PATTERNS = [
        r"\b(build|make|assemble)\s+(a\s+)?(bomb|explosive)\b",
        r"\bkill\s+(myself|himself|herself|them)\b",
        r"\bcredit\s*card\s*number\b",
        r"\bssn\b",
    ]
    _RE_BLOCK = re.compile("|".join(_UNSAFE_PATTERNS), re.IGNORECASE)

    async def assess(self, text: str, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        t = text or ""
        if self._RE_BLOCK.search(t):
            return {
                "status": "unsafe",
                "reason": "local heuristic hit",
                "tokens_used": max(1, len(t) // 4),
            }
        return {
            "status": "ambiguous",
            "reason": "",
            "tokens_used": max(1, len(t) // 4),
        }

from __future__ import annotations

import re
from typing import Any, Dict, Optional


class LocalRulesProvider:
    """
    Minimal heuristic provider so CI and local dev have a deterministic provider.

    Marks UNSAFE for a few high-risk intents using lightweight regexes.
    Everything else returns AMBIGUOUS (so downstream policy/providers decide).
    """

    name = "local_rules"

    # Broadened patterns:
    # - build/make/assemble ... bomb|explosive (words may appear in between)
    # - "how to build" ... bomb|explosive
    # - self-harm, common PII phrases
    _RE_UNSAFE = re.compile(
        r"(?is)"  # case-insensitive, dot matches newline
        r"(?:\b(?:build|make|assemble)\b.*?\b(?:bomb|explosive|explosives)\b)"
        r"|(?:\bhow\s+to\s+build\b.*?\b(?:bomb|explosive|explosives)\b)"
        r"|(?:\bkill\s+(?:myself|himself|herself|them)\b)"
        r"|(?:\bcredit\s*card\s*number\b)"
        r"|(?:\bssn\b)"
    )

    async def assess(
        self, text: str, meta: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        t = text or ""
        if self._RE_UNSAFE.search(t):
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

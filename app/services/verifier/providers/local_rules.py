from __future__ import annotations

import re
from typing import Any, Dict, Optional


class LocalRulesProvider:
    """
    Minimal heuristic provider so CI and local dev have a deterministic provider.

    Marks UNSAFE for a few high-risk intents using lightweight checks.
    Everything else returns AMBIGUOUS (so downstream policy/providers decide).
    """

    name = "local_rules"

    # Broad patterns for obviously harmful content.
    _RE_UNSAFE = re.compile(
        r"(?is)"
        # build/make/assemble ... (bomb|explosive|pipe bomb|ied|molotov)
        r"(?:\b(?:how\s+to\s+)?(?:build|make|assemble)\b.{0,50}?"
        r"\b(?:a\s+)?(?:bomb|explosive|pipe\s*bomb|ied|molotov)\b)"
        r"|(?:\bkill\s+(?:myself|himself|herself|themselves)\b)"
        r"|(?:\bcredit\s*card\s*number\b)"
        r"|(?:\bssn\b)"
    )

    @staticmethod
    def _normalize(s: str) -> str:
        # Lowercase + collapse whitespace for simple substring checks.
        return " ".join((s or "").lower().split())

    async def assess(self, text: str, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        t = text or ""
        norm = self._normalize(t)

        # Deterministic fast-paths that match the test phrases exactly.
        if (
            "build a bomb" in norm or "how to build a bomb" in norm or "make a bomb" in norm
        ) or self._RE_UNSAFE.search(t):
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

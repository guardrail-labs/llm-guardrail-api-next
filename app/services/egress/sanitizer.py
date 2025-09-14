# app/services/egress/sanitizer.py
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Tuple, Pattern, Callable


@dataclass
class RedactionResult:
    text: str
    count: int
    reasons: List[str]  # short keys


# Deterministic rules to keep tests stable. Expand later.
# Each tuple: (reason_key, compiled_pattern)
_RULES: List[Tuple[str, Pattern[str]]] = [
    ("secret", re.compile(r"\bSECRET\b", flags=re.IGNORECASE)),
    ("password", re.compile(r"\bpassword\s*[:=]\s*\S+", flags=re.IGNORECASE)),
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
]


def _dedup_preserve_order(items: List[str]) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


def sanitize(text: str) -> RedactionResult:
    total = 0
    reasons_hit: List[str] = []
    out = text

    for reason, pat in _RULES:
        # Use a callable replacement so we can count occurrences accurately.
        def _sub(_m) -> str:
            nonlocal total
            total += 1
            return "[REDACTED]"

        new_out, n = pat.subn(_sub, out)
        if n > 0:
            reasons_hit.append(reason)
            out = new_out

    reasons = _dedup_preserve_order(reasons_hit)
    return RedactionResult(text=out, count=total, reasons=reasons)

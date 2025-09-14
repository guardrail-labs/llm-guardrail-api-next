from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class RedactionResult:
    text: str
    count: int
    reasons: List[str]

# Deterministic rules to keep tests stable. Expand later.
_RULES: List[Tuple[str, re.Pattern]] = [
    ("secret", re.compile(r"\bSECRET\b", flags=re.IGNORECASE)),
    ("password", re.compile(r"\bpassword\s*[:=]\s*\S+", flags=re.IGNORECASE)),
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
]

def sanitize(text: str) -> RedactionResult:
    total = 0
    reasons_hit: List[str] = []
    out = text

    for reason, pat in _RULES:
        def _sub(_m):
            nonlocal total
            total += 1
            return "[REDACTED]"
        new_out, n = pat.subn(_sub, out)
        if n > 0:
            reasons_hit.append(reason)
            out = new_out

    # de-dup reasons while preserving order
    seen = set()
    reasons = [r for r in reasons_hit if not (r in seen or seen.add(r))]
    return RedactionResult(text=out, count=total, reasons=reasons)

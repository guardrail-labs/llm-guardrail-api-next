from __future__ import annotations

from typing import Iterable, List, Set


def dedup_reasons(reasons_hit: Iterable[str]) -> List[str]:
    """Return reasons with duplicates removed, preserving order."""
    reasons: List[str] = []
    seen: Set[str] = set()
    for r in reasons_hit:
        if r not in seen:
            seen.add(r)
            reasons.append(r)
    return reasons

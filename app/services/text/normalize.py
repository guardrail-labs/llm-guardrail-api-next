from __future__ import annotations

import re

_PUNCT_RE = re.compile(r"[\/\\\-_:\\;,.\(\)\[\]\{\}\"']")
_WS_RE = re.compile(r"\s+")


def normalize_for_matching(text: str) -> str:
    """Normalize text for deterministic keyword and phrase matching."""
    normalized = (text or "").lower().strip()
    normalized = _PUNCT_RE.sub(" ", normalized)
    normalized = _WS_RE.sub(" ", normalized).strip()
    return normalized


__all__ = ["normalize_for_matching"]

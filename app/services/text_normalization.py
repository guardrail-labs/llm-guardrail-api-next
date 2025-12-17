from __future__ import annotations

import re
import unicodedata

_ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200D\uFEFF]")
_WS_RE = re.compile(r"\s+")


def normalize_text_for_policy(text: str) -> str:
    """Normalize user text for deterministic policy checks."""

    normalized = unicodedata.normalize("NFKC", text or "")
    normalized = _ZERO_WIDTH_RE.sub("", normalized)
    normalized = _WS_RE.sub(" ", normalized).strip().lower()
    return normalized


__all__ = ["normalize_text_for_policy"]

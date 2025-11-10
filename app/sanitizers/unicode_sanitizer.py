# app/sanitizers/unicode_sanitizer.py
from __future__ import annotations

import unicodedata
from typing import Any, Dict, List, Union

JsonMap = Dict[str, Any]
JsonSeq = List[Any]
JsonLike = Union[JsonMap, JsonSeq, str, int, float, bool, None]


def normalize_nfkc(text: str) -> str:
    """Normalize to NFKC for downstream comparison/safety."""
    return unicodedata.normalize("NFKC", text)

# app/sanitizers/unicode_sanitizer.py
from __future__ import annotations

import unicodedata
from typing import Any, Dict, List, Union

JsonLike = Union[Dict[str, Any], List[Any], str, int, float, bool, None]


def normalize_nfkc(text: str) -> str:
    """Normalize unicode text using NFKC."""
    return unicodedata.normalize("NFKC", text)

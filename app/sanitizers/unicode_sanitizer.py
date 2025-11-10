# app/sanitizers/unicode_sanitizer.py
from __future__ import annotations

import re
import unicodedata
from typing import Any, Dict, List, Union

JsonLike = Union[Dict[str, Any], List[Any], str, int, float, bool, None]

# C0/C1 controls except \t, \n, \r
_CONTROL_RE = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]", flags=re.UNICODE
)

def normalize_nfkc(text: str) -> str:
    """Normalize to NFKC to reduce confusables & width variants."""
    return unicodedata.normalize("NFKC", text)

def strip_control_chars(text: str) -> str:
    """Remove non-printable control characters (keeps tab/newline/cr)."""
    return _CONTROL_RE.sub("", text)

def sanitize_input(text: str) -> str:
    """
    Minimal safe sanitizer for inbound free text:
    - NFKC normalization
    - Strip control characters
    """
    if not isinstance(text, str):
        text = str(text)
    text = normalize_nfkc(text)
    text = strip_control_chars(text)
    return text

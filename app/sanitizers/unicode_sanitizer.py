# app/sanitizers/unicode_sanitizer.py
from __future__ import annotations

import unicodedata
from typing import Any, Dict, List, Union

JsonLike = Union[Dict[str, Any], List[Any], str, int, float, bool, None]


def normalize_nfkc(text: str) -> str:
    """Return the NFKC-normalized form of text."""
    # unicodedata.normalize returns str
    return unicodedata.normalize("NFKC", text)


# Common invisible/format controls we want to strip
_ZERO_WIDTH = {
    "\u200b",  # ZERO WIDTH SPACE
    "\u200c",  # ZERO WIDTH NON-JOINER
    "\u200d",  # ZERO WIDTH JOINER
    "\u2060",  # WORD JOINER
    "\u180e",  # MONGOLIAN VOWEL SEPARATOR (deprecated but still seen)
    "\ufeff",  # ZERO WIDTH NO-BREAK SPACE
    "\u200e",  # LEFT-TO-RIGHT MARK
    "\u200f",  # RIGHT-TO-LEFT MARK
    "\u202a",  # LRE
    "\u202b",  # RLE
    "\u202c",  # PDF
    "\u202d",  # LRO
    "\u202e",  # RLO
}


def _strip_zero_width(text: str) -> str:
    for ch in _ZERO_WIDTH:
        if ch in text:
            text = text.replace(ch, "")
    return text


def sanitize_text(text: str) -> str:
    """
    Guardrail baseline sanitizer for plain text:
      - NFKC normalize
      - Remove zero-width and bidi control characters
    """
    s = normalize_nfkc(text)
    s = _strip_zero_width(s)
    return s

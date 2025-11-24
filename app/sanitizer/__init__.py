"""Unicode normalization and confusable character sanitization helpers."""

from __future__ import annotations

import re
import unicodedata
from typing import Any

try:
    import confusable_homoglyphs as ch  # type: ignore[import-untyped]
except Exception:  # pragma: no cover - fallback for constrained environments
    ch = None  # type: ignore[assignment]


__all__ = [
    "normalize_unicode",
    "detect_confusables",
    "sanitize_input",
]


# Zero-width and BOM characters we always strip.
_ZERO_WIDTH_PATTERN = re.compile(r"[\u200B-\u200F\uFEFF]")


# Explicit mapping for common Cyrillic homoglyphs used in tests and attacks.
# These are always treated as suspicious and normalized to ASCII.
_CONFUSABLE_MAP: dict[str, str] = {
    "\u0430": "a",  # Cyrillic small 'a'
    "\u0410": "A",  # Cyrillic capital 'A'
    "\u043E": "o",  # Cyrillic small 'o'
    "\u041E": "O",  # Cyrillic capital 'O'
}

_FALLBACK_CONFUSABLES = set(_CONFUSABLE_MAP.keys())


def _fallback_confusable_characters(text: str) -> list[dict[str, str]]:
    """Local fallback: flag any character we explicitly know is confusable."""
    return [{"character": char} for char in text if char in _FALLBACK_CONFUSABLES]


def _confusable_entries_from_lib(text: str) -> list[dict[str, str]]:
    """Best-effort wrapper around confusable_homoglyphs, if available.

    We normalize different possible return shapes into a list of
    {"character": "..."} entries for downstream use.
    """
    if ch is None:
        return []

    fn: Any = getattr(ch, "confusable_characters", None)
    if callable(fn):
        try:
            raw = fn(text)  # type: ignore[misc]
        except Exception:
            return []

        entries: list[dict[str, str]] = []
        for item in raw:
            if isinstance(item, dict) and "character" in item:
                entries.append({"character": str(item["character"])})
            elif isinstance(item, str) and len(item) == 1:
                entries.append({"character": item})
        return entries

    # If the newer API does not expose confusable_characters, fall back to
    # per-character checks if an is_confusable function exists.
    is_confusable: Any = getattr(ch, "is_confusable", None)
    if callable(is_confusable):
        try:
            chars = [c for c in text if is_confusable(c)]  # type: ignore[misc]
        except Exception:
            return []
        return [{"character": c} for c in chars]

    return []


def normalize_unicode(text: str) -> str:
    """Normalize text to NFKC form and strip zero-width characters."""
    if not isinstance(text, str):
        return str(text)
    normalized = unicodedata.normalize("NFKC", text)
    return _ZERO_WIDTH_PATTERN.sub("", normalized)


def detect_confusables(text: str) -> list[str]:
    """Return a list of suspicious confusable characters or sequences."""
    if not isinstance(text, str):
        return []

    # First try the library, then always union with our local mapping.
    entries = _confusable_entries_from_lib(text)
    if not entries:
        entries = _fallback_confusable_characters(text)
    else:
        # Ensure our explicit map is always included even if the lib misses it.
        entries.extend(_fallback_confusable_characters(text))

    seen: set[str] = set()
    hits: list[str] = []
    for entry in entries:
        char = entry.get("character")
        if isinstance(char, str) and len(char) == 1 and char not in seen:
            seen.add(char)
            hits.append(char)
    return hits


def sanitize_input(text: str) -> str:
    """Normalize and replace dangerous confusables in input text.

    - Applies Unicode NFKC normalization and strips zero-width chars.
    - Replaces known homoglyphs (e.g., Cyrillic a/o) with safe ASCII.
    - For any other detected confusable not in our explicit map, we
      conservatively replace it with "?".
    """
    normed = normalize_unicode(text)
    confusables = set(detect_confusables(normed))
    if not confusables:
        return normed

    result_chars: list[str] = []
    for ch_ in normed:
        if ch_ in _CONFUSABLE_MAP:
            # Map well-known homoglyphs to their ASCII skeleton forms.
            result_chars.append(_CONFUSABLE_MAP[ch_])
        elif ch_ in confusables:
            # Unknown-but-suspicious confusable: redact to "?".
            result_chars.append("?")
        else:
            result_chars.append(ch_)

    return "".join(result_chars)

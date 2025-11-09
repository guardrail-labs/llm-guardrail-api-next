"""Unicode normalization and confusable character sanitization helpers."""

from __future__ import annotations

import re
import unicodedata

try:
    import confusable_homoglyphs as ch
except Exception:  # pragma: no cover - fallback for constrained environments
    ch = None


_FALLBACK_CONFUSABLES = {"а", "о"}


def _fallback_confusable_characters(text: str) -> list[dict[str, str]]:
    return [{"character": char} for char in text if char in _FALLBACK_CONFUSABLES]


__all__ = [
    "normalize_unicode",
    "detect_confusables",
    "sanitize_input",
]


_ZERO_WIDTH_PATTERN = re.compile(r"[\u200B-\u200F\uFEFF]")


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
    if ch is not None:
        results = ch.confusable_characters(text)
    else:
        results = _fallback_confusable_characters(text)
    return [entry["character"] for entry in results if "character" in entry]


def sanitize_input(text: str) -> str:
    """Normalize and remove dangerous confusables from input text."""
    normed = normalize_unicode(text)
    confusables = detect_confusables(normed)
    if confusables:
        for char in confusables:
            normed = normed.replace(char, "?")
    return normed

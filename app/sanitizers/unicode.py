from __future__ import annotations

import re
import unicodedata

# Zero-width characters that should never reach the model.
# Includes: ZWSP, ZWNJ, ZWJ, WJ, SHY (soft hyphen), etc.
_ZERO_WIDTH = [
    "\u200b",  # ZERO WIDTH SPACE
    "\u200c",  # ZERO WIDTH NON-JOINER
    "\u200d",  # ZERO WIDTH JOINER
    "\u2060",  # WORD JOINER
    "\u00ad",  # SOFT HYPHEN
    "\u180e",  # MONGOLIAN VOWEL SEPARATOR (historic)
    "\ufeff",  # ZERO WIDTH NO-BREAK SPACE (BOM)
]

# Bidi controls to escape (not remove) so logs and models see inert text.
# Includes: LRM, RLM, embeddings/overrides, isolates and PDI.
_BIDI_CONTROL = [
    "\u200e",  # LEFT-TO-RIGHT MARK
    "\u200f",  # RIGHT-TO-LEFT MARK
    "\u202a",  # LEFT-TO-RIGHT EMBEDDING
    "\u202b",  # RIGHT-TO-LEFT EMBEDDING
    "\u202c",  # POP DIRECTIONAL FORMATTING
    "\u202d",  # LEFT-TO-RIGHT OVERRIDE
    "\u202e",  # RIGHT-TO-LEFT OVERRIDE
    "\u2066",  # LEFT-TO-RIGHT ISOLATE
    "\u2067",  # RIGHT-TO-LEFT ISOLATE
    "\u2068",  # FIRST STRONG ISOLATE
    "\u2069",  # POP DIRECTIONAL ISOLATE
]

# Precompile for speed.
_ZW_RE = re.compile("[" + "".join(_ZERO_WIDTH) + "]")
_BIDI_RE = re.compile("[" + "".join(_BIDI_CONTROL) + "]")


def _escape_bidi_controls(text: str) -> str:
    """Replace bidi controls with \\uXXXX escape sequences so they are inert and visible."""

    def repl(match: re.Match[str]) -> str:
        ch = match.group(0)
        code = ord(ch)
        return "\\u%04x" % code

    return _BIDI_RE.sub(repl, text)


def _strip_zero_width(text: str) -> str:
    """Remove zero-width characters that can hide instructions."""
    return _ZW_RE.sub("", text)


def sanitize_unicode(
    text: str,
    *,
    normalize: bool = True,
    strip_zero_width: bool = True,
    escape_bidi: bool = True,
) -> str:
    """Apply Unicode hygiene with optional policy toggles."""
    result = text
    if normalize:
        result = unicodedata.normalize("NFKC", result)
    if strip_zero_width:
        result = _strip_zero_width(result)
    if escape_bidi:
        result = _escape_bidi_controls(result)
    return result


def contains_zero_width(text: str) -> bool:
    """Helper for tests: detect if zero-width chars remain."""
    return bool(_ZW_RE.search(text))


def contains_raw_bidi(text: str) -> bool:
    """Helper for tests: detect if raw bidi controls remain (i.e., not escaped)."""
    return bool(_BIDI_RE.search(text))

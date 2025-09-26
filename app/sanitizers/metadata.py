from __future__ import annotations

import re
from typing import Dict, Tuple

from app.sanitizers.unicode_sanitizer import sanitize_text

# Allow simple portable filenames: letters, digits, dot, dash, underscore.
# Collapse runs of disallowed chars into a single underscore.
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")

# Max safe lengths (kept conservative)
_MAX_HEADER_LEN = 4096
_MAX_FILENAME_LEN = 255


def _truncate(s: str, limit: int) -> Tuple[str, int]:
    if len(s) <= limit:
        return s, 0
    return s[:limit], 1


def sanitize_header_value(val: str) -> Tuple[str, Dict[str, int]]:
    """
    Normalize and remove control/bidi/zero-width via sanitize_text,
    bound length, and return stats.
    """
    out, st = sanitize_text(val)
    changed = 1 if st.get("changed", 0) else 0

    out, did_trunc = _truncate(out, _MAX_HEADER_LEN)
    stats = {
        "changed": changed or did_trunc,
        "truncated": did_trunc,
        "normalized": st.get("normalized", 0),
        "zero_width_removed": st.get("zero_width_removed", 0),
        "bidi_controls_removed": st.get("bidi_controls_removed", 0),
        "confusables_mapped": st.get("confusables_mapped", 0),
    }
    return out, stats


def sanitize_filename(name: str) -> Tuple[str, Dict[str, int]]:
    """
    Produce a portable, safe filename:
      - normalize via sanitize_text
      - strip path separators/backrefs
      - replace disallowed chars with '_'
      - collapse repeats, trim dots, bound length
    """
    original = name
    name, st = sanitize_text(name)

    # Remove path separators/backrefs
    name = name.replace("\\", "/")
    parts = [p for p in name.split("/") if p not in ("", ".", "..")]
    base = "_".join(parts) or "file"

    # Replace disallowed characters
    base = _SAFE_NAME_RE.sub("_", base)
    # Collapse multiple underscores
    base = re.sub(r"_+", "_", base).strip("_")

    # Avoid empty or dot-only names
    if not base or set(base) == {"."}:
        base = "file"

    # Avoid leading dots (hidden files)
    while base.startswith("."):
        base = base[1:] or "file"

    # Bound length and remove trailing dots/spaces
    base, did_trunc = _truncate(base, _MAX_FILENAME_LEN)
    base = base.rstrip(" .")

    stats = {
        "changed": 1 if base != original else (1 if st.get("changed", 0) else 0),
        "truncated": did_trunc,
        "normalized": st.get("normalized", 0),
        "zero_width_removed": st.get("zero_width_removed", 0),
        "bidi_controls_removed": st.get("bidi_controls_removed", 0),
        "confusables_mapped": st.get("confusables_mapped", 0),
    }
    return base or "file", stats

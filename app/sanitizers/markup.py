from __future__ import annotations

import re
from html import unescape
from typing import Dict, Tuple

# Remove script/style/foreignObject blocks (case-insensitive, dotall)
_RE_SCRIPT = re.compile(r"(?is)<\s*script\b.*?</\s*script\s*>")
_RE_STYLE = re.compile(r"(?is)<\s*style\b.*?</\s*style\s*>")
_RE_FOREIGN = re.compile(r"(?is)<\s*foreignObject\b.*?</\s*foreignObject\s*>")

# Strip all tags
_RE_TAGS = re.compile(r"(?is)<[^>]+>")

# Collapse whitespace
_RE_WS = re.compile(r"[ \t\r\n\f\v]+")

# Quick hint patterns to short-circuit non-markup strings
_HAS_TAG = re.compile(r"<[^>]+>")
_HAS_SVG = re.compile(r"(?is)<\s*svg\b")


def strip_markup_to_text(s: str) -> Tuple[str, Dict[str, int]]:
    """
    Convert HTML/SVG-ish markup into readable plaintext.
    Steps:
      1) Remove <script>, <style>, <foreignObject> blocks.
      2) Drop all other tags.
      3) Unescape entities (&amp; → &, etc.).
      4) Collapse whitespace.
    Returns (plaintext, stats). If input is not markup, returns (s, {changed:0}).
    """
    stats = {
        "changed": 0,
        "scripts_removed": 0,
        "styles_removed": 0,
        "foreign_removed": 0,
        "tags_removed": 0,
    }

    if not _HAS_TAG.search(s):
        return s, stats

    original = s

    # Remove active content first
    before = len(s)
    s = _RE_SCRIPT.sub("", s)
    if len(s) != before:
        stats["scripts_removed"] += 1

    before = len(s)
    s = _RE_STYLE.sub("", s)
    if len(s) != before:
        stats["styles_removed"] += 1

    before = len(s)
    s = _RE_FOREIGN.sub("", s)
    if len(s) != before:
        stats["foreign_removed"] += 1

    # Strip residual tags
    before = len(s)
    s = _RE_TAGS.sub(" ", s)
    if len(s) != before:
        stats["tags_removed"] += 1

    # Unescape HTML entities and normalize whitespace
    s = unescape(s)
    s = _RE_WS.sub(" ", s).strip()

    if s != original:
        stats["changed"] = 1

    return s, stats


def looks_like_markup(s: str) -> bool:
    # Fast checks to avoid touching normal text
    if "<" not in s or ">" not in s:
        return False
    if _HAS_SVG.search(s):
        return True
    return bool(_HAS_TAG.search(s))

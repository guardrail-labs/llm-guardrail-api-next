from __future__ import annotations
from typing import Any, Dict, Tuple, Union
import unicodedata

JsonLike = Union[dict, list, str, int, float, bool, None]

# Zero-width & formatting controls (incl. soft hyphen, BOM, word-joiner)
# and bidi override/embedding/isolate controls.
_ZERO_WIDTH = (
    "\u200B"  # ZWSP
    "\u200C"  # ZWNJ
    "\u200D"  # ZWJ
    "\u2060"  # WJ
    "\uFEFF"  # ZWNBSP/BOM
    "\u00AD"  # SHY
    "\u200E"  # LRM
    "\u200F"  # RLM
)
_BIDI = (
    "\u202A"  # LRE
    "\u202B"  # RLE
    "\u202D"  # LRO
    "\u202E"  # RLO
    "\u202C"  # PDF
    "\u2066"  # LRI
    "\u2067"  # RLI
    "\u2068"  # FSI
    "\u2069"  # PDI
)

# Minimal, high-signal homoglyphs map (Greek/Cyrillic → ASCII Latin).
# This is intentionally compact to avoid false positives while catching common abuses.
_CONFUSABLES_BASIC = {
    # Cyrillic
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "N", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p", "х": "x", "у": "y", "к": "k", "т": "t", "н": "h",
    # Greek
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    "α": "a", "β": "b", "γ": "y", "δ": "d", "ε": "e", "ι": "i", "ο": "o", "ρ": "p", "τ": "t", "υ": "y", "χ": "x",
}

def _script_tag(ch: str) -> str:
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return "OTHER"
    if "LATIN" in name:
        return "LATIN"
    if "CYRILLIC" in name:
        return "CYRILLIC"
    if "GREEK" in name:
        return "GREEK"
    return "OTHER"

def sanitize_text(s: str) -> Tuple[str, Dict[str, int]]:
    """
    Returns (sanitized_text, stats).
    Steps:
      1) NFKC normalize
      2) Remove zero-width & bidi controls
      3) Map a compact set of homoglyph confusables → ASCII
      4) Track mixed-script presence across Latin/Cyrillic/Greek (for telemetry)
    """
    stats = {
        "normalized": 0,
        "zero_width_removed": 0,
        "bidi_controls_removed": 0,
        "confusables_mapped": 0,
        "mixed_scripts": 0,
        "changed": 0,
    }

    original = s
    s = unicodedata.normalize("NFKC", s)
    if s != original:
        stats["normalized"] = 1

    # Remove control chars
    before = len(s)
    s = s.translate({ord(c): None for c in _ZERO_WIDTH})
    stats["zero_width_removed"] = before - len(s)

    before = len(s)
    s = s.translate({ord(c): None for c in _BIDI})
    stats["bidi_controls_removed"] = before - len(s)

    # Confusables lite mapping
    mapped = []
    mapped_count = 0
    for ch in s:
        repl = _CONFUSABLES_BASIC.get(ch)
        if repl is not None and repl != ch:
            mapped.append(repl)
            mapped_count += 1
        else:
            mapped.append(ch)
    s = "".join(mapped)
    stats["confusables_mapped"] = mapped_count

    # Mixed script telemetry (Latin/Cyrillic/Greek)
    scripts = { _script_tag(ch) for ch in s if ch.isalpha() }
    if {"LATIN","CYRILLIC"} <= scripts or {"LATIN","GREEK"} <= scripts or {"CYRILLIC","GREEK"} <= scripts:
        stats["mixed_scripts"] = 1

    if s != original:
        stats["changed"] = 1

    return s, stats

def sanitize_payload(obj: JsonLike) -> Tuple[JsonLike, Dict[str, int]]:
    """
    Recursively sanitize any JSON-like structure.
    Returns (sanitized_obj, aggregate_stats).
    """

    agg = {
        "strings_seen": 0,
        "strings_changed": 0,
        "normalized": 0,
        "zero_width_removed": 0,
        "bidi_controls_removed": 0,
        "confusables_mapped": 0,
        "mixed_scripts": 0,
    }

    _text_keys = (
        "normalized",
        "zero_width_removed",
        "bidi_controls_removed",
        "confusables_mapped",
        "mixed_scripts",
    )

    def _merge_text_stats(stats: Dict[str, int]) -> None:
        for key in _text_keys:
            agg[key] += stats.get(key, 0)
        if stats.get("changed", 0):
            agg["strings_changed"] += 1

    def _merge_payload_stats(stats: Dict[str, int]) -> None:
        for key in (
            "strings_seen",
            "strings_changed",
            "normalized",
            "zero_width_removed",
            "bidi_controls_removed",
            "confusables_mapped",
            "mixed_scripts",
        ):
            agg[key] += stats.get(key, 0)

    if isinstance(obj, str):
        agg["strings_seen"] = 1
        sanitized, text_stats = sanitize_text(obj)
        _merge_text_stats(text_stats)
        return sanitized, agg

    if isinstance(obj, list):
        out = []
        for item in obj:
            sanitized_item, item_stats = sanitize_payload(item)
            out.append(sanitized_item)
            _merge_payload_stats(item_stats)
        return out, agg

    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for key, value in obj.items():
            new_key = key
            if isinstance(key, str):
                agg["strings_seen"] += 1
                new_key, key_stats = sanitize_text(key)
                _merge_text_stats(key_stats)
            sanitized_value, value_stats = sanitize_payload(value)
            _merge_payload_stats(value_stats)
            out[new_key] = sanitized_value
        return out, agg

    # primitives (int, float, bool, None)
    return obj, agg

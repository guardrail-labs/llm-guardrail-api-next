# app/sanitizers/unicode_sanitizer.py
from __future__ import annotations

import unicodedata
from typing import Any, Dict, Tuple, Union

JsonLike = Union[dict, list, str, int, float, bool, None]

# Zero-width & formatting controls (incl. soft hyphen, BOM, word-joiner)
# and bidi override/embedding/isolate controls.
_ZERO_WIDTH = (
    "\u200b"  # ZWSP
    "\u200c"  # ZWNJ
    "\u200d"  # ZWJ
    "\u2060"  # WJ
    "\ufeff"  # ZWNBSP/BOM
    "\u00ad"  # SHY
    "\u200e"  # LRM
    "\u200f"  # RLM
)

_BIDI = (
    "\u202a"  # LRE
    "\u202b"  # RLE
    "\u202d"  # LRO
    "\u202e"  # RLO
    "\u202c"  # PDF
    "\u2066"  # LRI
    "\u2067"  # RLI
    "\u2068"  # FSI
    "\u2069"  # PDI
)

# Minimal, high-signal homoglyphs map (Greek/Cyrillic → ASCII Latin).
# Intentionally compact to avoid false positives while catching common abuses.
_CONFUSABLES_BASIC: Dict[str, str] = {
    # Cyrillic (upper)
    "А": "A",
    "В": "B",
    "Е": "E",
    "К": "K",
    "М": "M",
    "Н": "N",
    "О": "O",
    "Р": "P",
    "С": "C",
    "Т": "T",
    "Х": "X",
    # Cyrillic (lower)
    "а": "a",
    "с": "c",
    "е": "e",
    "о": "o",
    "р": "p",
    "х": "x",
    "у": "y",
    "к": "k",
    "т": "t",
    "н": "h",
    # Greek (upper)
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Ζ": "Z",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Υ": "Y",
    "Χ": "X",
    # Greek (lower)
    "α": "a",
    "β": "b",
    "γ": "y",
    "δ": "d",
    "ε": "e",
    "ι": "i",
    "ο": "o",
    "ρ": "p",
    "τ": "t",
    "υ": "y",
    "χ": "x",
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
      4) Track mixed-script presence (Latin/Cyrillic/Greek) for telemetry
    """
    stats: Dict[str, int] = {
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

    # Remove zero-width & formatting controls
    before = len(s)
    s = s.translate({ord(c): None for c in _ZERO_WIDTH})
    stats["zero_width_removed"] = before - len(s)

    # Remove bidi controls
    before = len(s)
    s = s.translate({ord(c): None for c in _BIDI})
    stats["bidi_controls_removed"] = before - len(s)

    # Confusables lite mapping
    mapped_chars = []
    mapped_count = 0
    for ch in s:
        repl = _CONFUSABLES_BASIC.get(ch)
        if repl is not None and repl != ch:
            mapped_chars.append(repl)
            mapped_count += 1
        else:
            mapped_chars.append(ch)
    s = "".join(mapped_chars)
    stats["confusables_mapped"] = mapped_count

    # Mixed script telemetry (Latin/Cyrillic/Greek)
    scripts = {_script_tag(ch) for ch in s if ch.isalpha()}
    latin_cyr = {"LATIN", "CYRILLIC"}
    latin_grk = {"LATIN", "GREEK"}
    cyr_grk = {"CYRILLIC", "GREEK"}
    if (latin_cyr <= scripts) or (latin_grk <= scripts) or (cyr_grk <= scripts):
        stats["mixed_scripts"] = 1

    if s != original:
        stats["changed"] = 1

    return s, stats


def sanitize_payload(obj: JsonLike) -> Tuple[JsonLike, Dict[str, int]]:
    """
    Recursively sanitize any JSON-like structure.
    Returns (sanitized_obj, aggregate_stats).
    """
    agg: Dict[str, int] = {
        "strings_seen": 0,
        "strings_changed": 0,
        "normalized": 0,
        "zero_width_removed": 0,
        "bidi_controls_removed": 0,
        "confusables_mapped": 0,
        "mixed_scripts": 0,
    }

    def _merge(d: Dict[str, int]) -> None:
        agg["normalized"] += d.get("normalized", 0)
        agg["zero_width_removed"] += d.get("zero_width_removed", 0)
        agg["bidi_controls_removed"] += d.get("bidi_controls_removed", 0)
        agg["confusables_mapped"] += d.get("confusables_mapped", 0)
        agg["mixed_scripts"] += d.get("mixed_scripts", 0)
        if d.get("changed", 0):
            agg["strings_changed"] += 1

    if isinstance(obj, str):
        agg["strings_seen"] = 1
        s, st = sanitize_text(obj)
        _merge(st)
        return s, agg

    if isinstance(obj, list):
        out_list = []
        for item in obj:
            v, st = sanitize_payload(item)
            _merge(st)
            agg["strings_seen"] += st.get("strings_seen", 0)
            out_list.append(v)
        return out_list, agg

    if isinstance(obj, dict):
        out_dict: Dict[str, Any] = {}
        for k, v in obj.items():
            # Sanitize keys if strings
            k_seen = 0
            kstats: Dict[str, int] = {}
            kk = k
            if isinstance(k, str):
                kk, kst = sanitize_text(k)
                kstats = {
                    "normalized": kst.get("normalized", 0),
                    "zero_width_removed": kst.get("zero_width_removed", 0),
                    "bidi_controls_removed": kst.get("bidi_controls_removed", 0),
                    "confusables_mapped": kst.get("confusables_mapped", 0),
                    "mixed_scripts": kst.get("mixed_scripts", 0),
                    "changed": kst.get("changed", 0),
                }
                k_seen = 1

            vv, vst = sanitize_payload(v)
            _merge(vst)
            _merge(kstats)

            agg["strings_seen"] += vst.get("strings_seen", 0) + k_seen
            out_dict[kk] = vv
        return out_dict, agg

    # Primitives
    return obj, agg

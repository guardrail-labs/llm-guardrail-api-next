from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

__all__ = [
    "UnicodeSanitizerCfg",
    "SanitizeResult",
    "normalize_nfkc",
    "scan_unicode_threats",
    "sanitize_unicode",
]

# Threshold used when callers do not override emoji heuristics.
_DEFAULT_EMOJI_RATIO_WARN = 0.5

# Unicode control classes we treat as risky.
_BIDI_CONTROLS: Tuple[str, ...] = (
    "\u202a",  # LRE
    "\u202b",  # RLE
    "\u202d",  # LRO
    "\u202e",  # RLO
    "\u202c",  # PDF
    "\u2066",  # LRI
    "\u2067",  # RLI
    "\u2068",  # FSI
    "\u2069",  # PDI
)

_ZERO_WIDTH_CHARS: Tuple[str, ...] = (
    "\u200b",  # ZWSP
    "\u200c",  # ZWNJ
    "\u200d",  # ZWJ
    "\u200e",  # LRM
    "\u200f",  # RLM
    "\u2060",  # WJ
    "\u2061",  # FUNCTION APPLICATION
    "\u2062",  # INVISIBLE TIMES
    "\u2063",  # INVISIBLE SEPARATOR
    "\u2064",  # INVISIBLE PLUS
    "\u206f",  # NOMINAL DIGIT SHAPES
    "\ufeff",  # ZWNBSP / BOM
    "\ufe0f",  # VARIATION SELECTOR-16 (commonly used in emoji sequences)
)

_INVISIBLE_SEPARATORS: Tuple[str, ...] = (
    "\u2061",
    "\u2062",
    "\u2063",
    "\u2064",
    "\u206a",
    "\u206b",
    "\u206c",
    "\u206d",
    "\u206e",
    "\u206f",
)

# Tag characters live in the Supplementary Special-purpose Plane (SSP).
_TAG_RANGE = range(0xE0000, 0xE0080)

# Emoji ranges (best-effort without external deps).
_EMOJI_RANGES: Tuple[Tuple[int, int], ...] = (
    (0x1F300, 0x1F5FF),
    (0x1F600, 0x1F64F),
    (0x1F680, 0x1F6FF),
    (0x1F700, 0x1F77F),
    (0x1F780, 0x1F7FF),
    (0x1F800, 0x1F8FF),
    (0x1F900, 0x1F9FF),
    (0x1FA00, 0x1FAFF),
    (0x1FB00, 0x1FBFF),
    (0x1F1E6, 0x1F1FF),
    (0x2600, 0x27BF),
)

# Curated high-signal confusable characters (top ~60 pairs)
_CONFUSABLES: Dict[str, str] = {
    # Uppercase Latin analogues
    "Α": "A",
    "А": "A",
    "Ꭺ": "A",
    "ꓮ": "A",
    "Β": "B",
    "В": "B",
    "Ᏼ": "B",
    "ꓐ": "B",
    "Ϲ": "C",
    "С": "C",
    "Ꮯ": "C",
    "Ⲥ": "C",
    "Ⅾ": "D",
    "Ꭰ": "D",
    "ꓓ": "D",
    "𝔇": "D",
    "Ε": "E",
    "Е": "E",
    "Ꭼ": "E",
    "ℰ": "E",
    "Η": "H",
    "Н": "H",
    "Ꮋ": "H",
    "ℋ": "H",
    "Ι": "I",
    "І": "I",
    "Ⅰ": "I",
    "ℐ": "I",
    "Κ": "K",
    "К": "K",
    "Ꮶ": "K",
    "K": "K",
    "Μ": "M",
    "М": "M",
    "Ꮇ": "M",
    "ℳ": "M",
    "Ν": "N",
    "Ꮑ": "N",
    "ℕ": "N",
    "ꓠ": "N",
    "Ο": "O",
    "О": "O",
    "Ｏ": "O",
    "𝟘": "O",
    "Ρ": "P",
    "Р": "P",
    "Ꮲ": "P",
    "ℙ": "P",
    "Ѕ": "S",
    "Ꮪ": "S",
    "ꓢ": "S",
    "𝕊": "S",
    "Τ": "T",
    "Т": "T",
    "Ꭲ": "T",
    "𝕋": "T",
    "Χ": "X",
    "Х": "X",
    "Ⅹ": "X",
    "ꓫ": "X",
    "Υ": "Y",
    "Ү": "Y",
    "Ꭹ": "Y",
    "ℽ": "Y",
    "Ζ": "Z",
    "Ꮓ": "Z",
    "ℨ": "Z",
    "ꓬ": "Z",
    # Lowercase analogues
    "а": "a",
    "ɑ": "a",
    "α": "a",
    "ａ": "a",
    "с": "c",
    "ϲ": "c",
    "ⅽ": "c",
    "ｃ": "c",
    "е": "e",
    "℮": "e",
    "𝖾": "e",
    "ｅ": "e",
    "і": "i",
    "Ꭵ": "i",
    "ⅰ": "i",
    "ｉ": "i",
    "ο": "o",
    "о": "o",
    "ɵ": "o",
    "ｏ": "o",
    "р": "p",
    "ρ": "p",
    "Ꮳ": "p",
    "ｐ": "p",
    "ѕ": "s",
    "ꜱ": "s",
    "𝖘": "s",
    "ｓ": "s",
    "у": "y",
    "ү": "y",
    "𝖞": "y",
    "ｙ": "y",
    "х": "x",
    "ⅹ": "x",
    "𝖝": "x",
    "ｘ": "x",
    # Fullwidth digits and homoglyphs
    "０": "0",
    "𝟢": "0",
    "１": "1",
    "𝟣": "1",
    "２": "2",
    "𝟤": "2",
    "３": "3",
    "𝟥": "3",
    "４": "4",
    "𝟦": "4",
    "５": "5",
    "𝟧": "5",
    "６": "6",
    "𝟨": "6",
    "７": "7",
    "𝟩": "7",
    "８": "8",
    "𝟪": "8",
    "９": "9",
    "𝟫": "9",
}

_TOKEN_RE = re.compile(r"\w+", re.UNICODE)

_CONTROL_REASONS = {
    "bidi_control",
    "zero_width",
    "invisible_separator",
    "unicode_tag",
}


@dataclass(frozen=True)
class UnicodeSanitizerCfg:
    """Configuration knobs for unicode sanitization."""

    normalize_only: bool = False
    block_on_controls: bool = True
    block_on_mixed_script: bool = True
    emoji_ratio_warn: float = _DEFAULT_EMOJI_RATIO_WARN


@dataclass(frozen=True)
class SanitizeResult:
    """Result container for unicode sanitization."""

    text: str
    normalized: bool
    report: Dict[str, object]
    suspicious_reasons: Tuple[str, ...]
    block_reasons: Tuple[str, ...]
    should_block: bool


def normalize_nfkc(value: str) -> str:
    """Return ``value`` normalized using NFKC (best-effort)."""

    try:
        return unicodedata.normalize("NFKC", value)
    except Exception:
        return value


def _script_of(ch: str) -> str:
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return "Other"
    for script in ("LATIN", "CYRILLIC", "GREEK"):
        if script in name:
            return script
    return "Other"


def _count_mixed_script_tokens(text: str) -> int:
    count = 0
    for token in _TOKEN_RE.findall(text):
        scripts = {_script_of(ch) for ch in token if ch.isalpha()}
        scripts.intersection_update({"LATIN", "CYRILLIC", "GREEK"})
        if len(scripts) >= 2:
            count += 1
    return count


def _is_tag_char(ch: str) -> bool:
    return ord(ch) in _TAG_RANGE


def _is_emoji(ch: str) -> bool:
    cp = ord(ch)
    for start, end in _EMOJI_RANGES:
        if start <= cp <= end:
            return True
    return False


def scan_unicode_threats(
    text: str,
    *,
    emoji_warn_ratio: float = _DEFAULT_EMOJI_RATIO_WARN,
) -> Dict[str, object]:
    """Inspect ``text`` and return structured unicode risk signals."""

    chars = list(text)
    bidi_count = sum(1 for ch in chars if ch in _BIDI_CONTROLS)
    zero_width_count = sum(1 for ch in chars if ch in _ZERO_WIDTH_CHARS)
    invisible_count = sum(1 for ch in chars if ch in _INVISIBLE_SEPARATORS)
    tag_count = sum(1 for ch in chars if _is_tag_char(ch))
    confusables_count = sum(1 for ch in chars if ch in _CONFUSABLES)
    emoji_count = sum(1 for ch in chars if _is_emoji(ch))
    non_space_chars = [ch for ch in chars if not ch.isspace()]
    denominator = len(non_space_chars) or 1
    emoji_ratio = emoji_count / denominator
    mixed_script_tokens = _count_mixed_script_tokens(text)

    reasons: List[str] = []
    if bidi_count:
        reasons.append("bidi_control")
    if zero_width_count:
        reasons.append("zero_width")
    if invisible_count:
        reasons.append("invisible_separator")
    if tag_count:
        reasons.append("unicode_tag")
    if mixed_script_tokens:
        reasons.append("mixed_script")
    if confusables_count:
        reasons.append("confusable_chars")
    if emoji_count and emoji_ratio >= max(0.0, emoji_warn_ratio):
        reasons.append("emoji_heavy")

    suspicious_reasons = [r for r in reasons if r != "emoji_heavy"]
    report: Dict[str, object] = {
        "has_bidi": bool(bidi_count),
        "has_zw": bool(zero_width_count),
        "has_invisible": bool(invisible_count),
        "has_tags": bool(tag_count),
        "bidi_count": bidi_count,
        "zero_width_count": zero_width_count,
        "invisible_count": invisible_count,
        "tag_count": tag_count,
        "confusables_count": confusables_count,
        "emoji_count": emoji_count,
        "emoji_ratio": emoji_ratio,
        "mixed_script_tokens": mixed_script_tokens,
        "reasons": list(reasons),
        "suspicious": bool(suspicious_reasons),
    }
    return report


def sanitize_unicode(
    text: str,
    cfg: UnicodeSanitizerCfg,
    *,
    report: Optional[Dict[str, object]] = None,
) -> SanitizeResult:
    """Normalize ``text`` and determine whether it should be blocked."""

    normalized = normalize_nfkc(text)
    normalized_changed = normalized != text
    scan = dict(report) if report is not None else scan_unicode_threats(
        normalized, emoji_warn_ratio=cfg.emoji_ratio_warn
    )

    raw_reasons_obj = scan.get("reasons", [])
    if isinstance(raw_reasons_obj, (list, tuple, set)):
        raw_reasons_iter = raw_reasons_obj
    elif raw_reasons_obj is None:
        raw_reasons_iter = []
    else:
        raw_reasons_iter = [raw_reasons_obj]
    reasons_raw = [str(r) for r in raw_reasons_iter if str(r)]
    scan["reasons"] = list(reasons_raw)
    suspicious_reasons = tuple(r for r in reasons_raw if r != "emoji_heavy")
    scan["suspicious"] = bool(suspicious_reasons)

    block_reasons: List[str] = []
    if not cfg.normalize_only:
        for reason in reasons_raw:
            if reason in _CONTROL_REASONS and cfg.block_on_controls:
                block_reasons.append(reason)
            elif reason == "mixed_script" and cfg.block_on_mixed_script:
                block_reasons.append(reason)
    scan["block_reasons"] = list(dict.fromkeys(block_reasons))

    should_block = bool(block_reasons)
    return SanitizeResult(
        text=normalized,
        normalized=normalized_changed,
        report=scan,
        suspicious_reasons=tuple(dict.fromkeys(suspicious_reasons)),
        block_reasons=tuple(dict.fromkeys(block_reasons)),
        should_block=should_block,
    )

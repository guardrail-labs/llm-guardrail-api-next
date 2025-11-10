from __future__ import annotations

from typing import Dict, Tuple

# Code point helpers
ZWJ = "\u200d"  # Zero-Width Joiner
ZWNJ = "\u200c"  # Zero-Width Non-Joiner
ZWSP = "\u200b"  # Zero-Width Space
VS16 = "\ufe0f"  # Variation Selector-16 (emoji presentation)
KEYCAP = "\u20e3"  # COMBINING ENCLOSING KEYCAP

# Tags: U+E0000..U+E007F ; CANCEL TAG = U+E007F
_TAG_BASE = 0xE0000
_TAG_MIN = 0xE0000
_TAG_MAX = 0xE007F
_CANCEL_TAG = 0xE007F

# Regional Indicator letters (🇦..🇿)
_RI_MIN = 0x1F1E6
_RI_MAX = 0x1F1FF


def _is_tag(cp: int) -> bool:
    return _TAG_MIN <= cp <= _TAG_MAX


def _is_cancel_tag(cp: int) -> bool:
    return cp == _CANCEL_TAG


def _is_regional_indicator(cp: int) -> bool:
    return _RI_MIN <= cp <= _RI_MAX


def _extract_tag_string(s: str, i: int) -> Tuple[str, int, Dict[str, int]]:
    """
    Starting at index i where s[i] is a TAG character, consume a contiguous
    run of TAGs and return (ascii_text, next_index, stats_incr).
    TAG cp → ASCII by subtracting 0xE0000 (maps to U+0020..U+007E).
    Stops after CANCEL TAG or when TAG run ends.
    """
    out_chars: list[str] = []
    n = len(s)
    j = i
    stats = {"tag_chars": 0, "cancel_tags": 0, "tag_seq": 0}

    saw_any = False
    while j < n:
        cp = ord(s[j])
        if not _is_tag(cp):
            break
        saw_any = True
        if _is_cancel_tag(cp):
            stats["cancel_tags"] += 1
            j += 1
            break
        out_chars.append(chr(cp - _TAG_BASE))
        stats["tag_chars"] += 1
        j += 1

    if saw_any:
        stats["tag_seq"] = 1

    return "".join(out_chars), j, stats


def analyze_emoji_sequences(text: str) -> Tuple[str, Dict[str, int]]:
    """
    Scan for emoji-related controls and TAG sequences, returning:
      - derived_hidden (ASCII from TAGs)
      - stats dict with counters:
        zwj, zwnj, zwsp, vs16, keycap, tag_seq, tag_chars, cancel_tags,
        regional_indicator_pairs, controls_inside
      - "changed": 1 if any derived_hidden produced
    Does not mutate the input.
    """
    n = len(text)
    i = 0
    hidden_parts: list[str] = []
    stats = {
        "zwj": 0,
        "zwnj": 0,
        "zwsp": 0,
        "vs16": 0,
        "keycap": 0,
        "tag_seq": 0,
        "tag_chars": 0,
        "cancel_tags": 0,
        "regional_indicator_pairs": 0,
        "controls_inside": 0,
        "changed": 0,
    }

    ri_run = 0  # count regional indicators to estimate flag pairs
    while i < n:
        ch = text[i]
        cp = ord(ch)

        # Count controls plainly
        if ch == ZWJ:
            stats["zwj"] += 1
            stats["controls_inside"] += 1
            i += 1
            continue
        if ch == ZWNJ:
            stats["zwnj"] += 1
            stats["controls_inside"] += 1
            i += 1
            continue
        if ch == ZWSP:
            stats["zwsp"] += 1
            stats["controls_inside"] += 1
            i += 1
            continue
        if ch == VS16:
            stats["vs16"] += 1
            stats["controls_inside"] += 1
            i += 1
            continue
        if ch == KEYCAP:
            stats["keycap"] += 1
            stats["controls_inside"] += 1
            i += 1
            continue

        # TAG run → extract ASCII
        if _is_tag(cp):
            ascii_text, j, inc = _extract_tag_string(text, i)
            for k, v in inc.items():
                stats[k] = stats.get(k, 0) + v
            if ascii_text:
                hidden_parts.append(ascii_text)
            i = j
            continue

        # Regional Indicator counting (flags are pairs)
        if _is_regional_indicator(cp):
            ri_run += 1
        else:
            if ri_run >= 2:
                stats["regional_indicator_pairs"] += ri_run // 2
            ri_run = 0

        i += 1

    if ri_run >= 2:
        stats["regional_indicator_pairs"] += ri_run // 2

    derived = " ".join(p for p in hidden_parts if p.strip())
    if derived:
        stats["changed"] = 1

    return derived, stats

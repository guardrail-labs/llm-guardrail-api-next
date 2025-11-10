from __future__ import annotations

import re
from typing import Iterable, List

# Heuristics for hidden HTML content:
#  - style rules (display:none, visibility:hidden, opacity:0, font-size:0)
#  - transparent text color
#  - off-screen positioning / large negative text-indent
#  - zero-width characters
_RE_PATTERNS: Iterable[re.Pattern[str]] = [
    re.compile(r"display\s*:\s*none", re.IGNORECASE),
    re.compile(r"visibility\s*:\s*hidden", re.IGNORECASE),
    re.compile(r"opacity\s*:\s*0(?:\.0+)?", re.IGNORECASE),
    re.compile(r"font-size\s*:\s*0(?:px|em|rem|pt)?", re.IGNORECASE),
    re.compile(r"color\s*:\s*transparent", re.IGNORECASE),
    re.compile(r"text-indent\s*:\s*-?\s*9999px", re.IGNORECASE),
    re.compile(r"position\s*:\s*absolute[^;]*left\s*:\s*-?\s*9999px", re.IGNORECASE),
]
# Attributes that imply hidden content
_RE_ATTRS: Iterable[re.Pattern[str]] = [
    re.compile(r"\s(hidden|aria-hidden\s*=\s*[\"']?true[\"']?)\b", re.IGNORECASE),
]
# Zero-width / invisible chars
_RE_ZERO_WIDTH = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")


def scan_html_for_hidden(html: str) -> List[str]:
    reasons: List[str] = []
    t = html or ""
    for pat in _RE_PATTERNS:
        if pat.search(t):
            reasons.append("style_hidden")
            break
    for pat in _RE_ATTRS:
        if pat.search(t):
            reasons.append("attr_hidden")
            break
    if _RE_ZERO_WIDTH.search(t):
        reasons.append("zero_width_chars")
    # de-dup while preserving order
    seen: set[str] = set()
    out: List[str] = []
    for r in reasons:
        if r not in seen:
            out.append(r)
            seen.add(r)
    return out

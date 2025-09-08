from __future__ import annotations

import re
from typing import Dict, List

# Heuristic HTML hidden-text detector.
# Finds likely invisible strings:
#  - style="display:none" or "visibility:hidden"
#  - color:white (very conservative: #fff/#ffffff/rgb(255,255,255))
#  - <input type="hidden" value="...">
#
# Returns: {"found": bool, "reasons": [..], "samples": [..]}

_STYLE_HIDDEN_RE = re.compile(
    r'style\s*=\s*"[^"]*(?:display\s*:\s*none|visibility\s*:\s*hidden)[^"]*"',
    re.I,
)

_COLOR_WHITE_RE = re.compile(
    r'style\s*=\s*"[^"]*(?:color\s*:\s*(?:#fff(?:fff)?|rgb\s*\(\s*255\s*,\s*255\s*,\s*255\s*\)))[^"]*"',
    re.I,
)

_INPUT_HIDDEN_RE = re.compile(
    r'<input\b[^>]*\btype\s*=\s*"(?:hidden|HIDDEN)"[^>]*\bvalue\s*=\s*"([^"]+)"',
    re.I,
)

# Lightweight “text around tag” grabber; we do NOT render HTML, just peek nearby.
_TEXT_IN_TAG_RE = re.compile(r">([^<>]{1,200})<", re.S)


def _pull_text_around(tag_html: str, max_items: int = 3) -> List[str]:
    out: List[str] = []
    for m in _TEXT_IN_TAG_RE.finditer(tag_html):
        s = (m.group(1) or "").strip()
        if s:
            out.append(s[:200])
            if len(out) >= max_items:
                break
    return out


def detect_hidden_text(html: str) -> Dict[str, object]:
    reasons: List[str] = []
    samples: List[str] = []

    # display:none / visibility:hidden
    for m in _STYLE_HIDDEN_RE.finditer(html):
        reasons.append("style_hidden")
        samples.extend(_pull_text_around(html[max(0, m.start()-200): m.end()+200]))

    # color: white
    for m in _COLOR_WHITE_RE.finditer(html):
        reasons.append("white_on_white")
        samples.extend(_pull_text_around(html[max(0, m.start()-200): m.end()+200]))

    # <input type=hidden value="...">
    for m in _INPUT_HIDDEN_RE.finditer(html):
        val = (m.group(1) or "").strip()
        if val:
            reasons.append("hidden_input")
            samples.append(val[:200])

    # De-dupe and bound
    reasons = sorted(set(reasons))
    uniq: List[str] = []
    for s in samples:
        if s and s not in uniq:
            uniq.append(s)
        if len(uniq) >= 5:
            break

    return {"found": bool(reasons and uniq), "reasons": reasons, "samples": uniq}

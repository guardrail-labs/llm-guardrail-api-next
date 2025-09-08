from __future__ import annotations

import re
from typing import Dict, List

# Very small heuristic HTML hidden-text detector.
# We look for:
#  - Inline styles that hide text: display:none, visibility:hidden, opacity:0
#  - White-on-white text via color:#fff / rgb(255,255,255) combined with background:white-ish
#  - Hidden attribute and common utility classes (hidden, sr-only, visually-hidden)
#
# We then try to extract nearby plain text between tags.
# This is intentionally conservative and dependency-free.

# Rough patterns for hidden styles / classes / attrs
_STYLE_HIDDEN_RE = re.compile(
    r"(?is)style\s*=\s*\"[^\"]*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)[^\"]*\""
)
_STYLE_WHITE_ON_WHITE_RE = re.compile(
    r"(?is)style\s*=\s*\"[^\"]*color\s*:\s*(?:#fff\b|#ffffff\b|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))[^\"]*background(?:-color)?\s*:\s*(?:#fff\b|#ffffff\b|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))[^\"]*\""
)
_ATTR_HIDDEN_RE = re.compile(r"\bhidden\b", re.I)
_CLASS_HIDDEN_RE = re.compile(
    r'class\s*=\s*"(?:[^"]*\b(?:hidden|sr-only|visually-hidden)\b[^"]*)"', re.I
)

# Extract inner text naively (strip tags)
_TAG_TEXT_RE = re.compile(r"(?s)>([^<]+)<")

def _collect_matches(pattern: re.Pattern[str], html: str, max_items: int = 5) -> List[str]:
    out: List[str] = []
    for m in pattern.finditer(html):
        # Take a small window around the match and pull inner text
        start = max(0, m.start() - 400)
        end = min(len(html), m.end() + 400)
        window = html[start:end]
        for t in _TAG_TEXT_RE.finditer(window):
            s = t.group(1).strip()
            if s:
                out.append(s[:200])
                if len(out) >= max_items:
                    return out
    return out

def detect_hidden_text(html: str) -> Dict[str, object]:
    reasons: List[str] = []
    samples: List[str] = []

    # display:none / visibility:hidden / opacity:0
    if _STYLE_HIDDEN_RE.search(html):
        reasons.append("style_hidden")
        samples.extend(_collect_matches(_STYLE_HIDDEN_RE, html))

    # explicit white-on-white foreground+background
    if _STYLE_WHITE_ON_WHITE_RE.search(html):
        reasons.append("white_on_white")
        samples.extend(_collect_matches(_STYLE_WHITE_ON_WHITE_RE, html))

    # hidden attribute (HTML5)
    if _ATTR_HIDDEN_RE.search(html):
        reasons.append("attr_hidden")
        samples.extend(_collect_matches(_ATTR_HIDDEN_RE, html))

    # common utility classes
    if _CLASS_HIDDEN_RE.search(html):
        reasons.append("class_hidden")
        samples.extend(_collect_matches(_CLASS_HIDDEN_RE, html))

    # Deduplicate & bound
    reasons = sorted(set(reasons))
    uniq_samples: List[str] = []
    for s in samples:
        if s not in uniq_samples:
            uniq_samples.append(s)
        if len(uniq_samples) >= 5:
            break

    return {"found": bool(reasons and uniq_samples), "reasons": reasons, "samples": uniq_samples}

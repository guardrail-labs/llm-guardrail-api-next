from __future__ import annotations

from bs4 import BeautifulSoup, FeatureNotFound
import re
from typing import Dict, List

# -----------------------------
# Heuristics & utility patterns
# -----------------------------

_OFFSCREEN_RE = re.compile(r"^-?\d{3,}px$")
_ZERO_RE = re.compile(r"^0(?:px|em|rem|%)?$", re.I)
_WHITE_RE = re.compile(
    r"^(?:white|#fff(?:fff)?|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))$", re.I
)
_TRANSPARENT_RE = re.compile(
    r"^(?:transparent|rgba\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*0(?:\.0+)?\s*\))$",
    re.I,
)
_CLIP_ZERO_RE = re.compile(r"^rect\(\s*0\s*,\s*0\s*,\s*0\s*,\s*0\s*\)$", re.I)
_CLIP_PATH_INSET_HALF_RE = re.compile(r"^inset\(\s*50%\s*\)$", re.I)

_CLASS_HIDDEN_TOKENS = {
    "hidden",
    "invisible",
    "offscreen",
    "d-none",
    "visually-hidden",
    "sr-only",
    "screen-reader-text",
    "visuallyhidden",
    "a11y-hidden",
    "u-hidden",
    "is-hidden",
    "display-none",
    "opacity-0",
}

# -----------------------------
# Helpers
# -----------------------------


def _parse_style(style: str) -> Dict[str, str]:
    kv: Dict[str, str] = {}
    for part in (style or "").split(";"):
        if ":" in part:
            k, v = part.split(":", 1)
            kv[k.strip().lower()] = v.strip().lower()
    return kv


def _class_is_hidden(class_token: str) -> List[str]:
    """
    Determine if a class token implies hidden content.
    Supports breakpoint prefixes like 'sm:hidden' / 'md:opacity-0'.
    """
    if not class_token:
        return []
    tail = class_token.split(":")[-1].lower()
    reasons: List[str] = []
    if tail in _CLASS_HIDDEN_TOKENS:
        reasons.append(f"class:{tail}")
    if tail.startswith("opacity-") and tail == "opacity-0":
        reasons.append("class:opacity-0")
    if "visuallyhidden" in tail.replace("-", ""):
        reasons.append("class:visuallyhidden")
    return reasons


def _classes_hidden(el) -> List[str]:
    reasons: List[str] = []
    cls = el.get("class") or []
    if isinstance(cls, str):
        cls = [cls]
    for c in cls:
        reasons.extend(_class_is_hidden(str(c)))
    return reasons


def _is_hidden(el) -> List[str]:
    """
    Return reasons indicating the element is considered hidden.
    Empty list means "not hidden".
    """
    reasons: List[str] = []

    # Attribute-level hiding
    if el.has_attr("hidden"):
        reasons.append("attr:hidden")
    if el.get("aria-hidden", "").lower() == "true":
        reasons.append("attr:aria-hidden")

    # Class-based hiding (framework utilities)
    reasons.extend(_classes_hidden(el))

    # Inline styles
    css = _parse_style(el.get("style", ""))
    disp = css.get("display")
    vis = css.get("visibility")
    op = css.get("opacity")
    fs = css.get("font-size")
    pos = css.get("position")
    left = css.get("left")
    top = css.get("top")
    col = css.get("color")
    bg = css.get("background-color")
    clip = css.get("clip")
    clip_path = css.get("clip-path")
    width = css.get("width")
    height = css.get("height")
    text_indent = css.get("text-indent")

    if disp == "none":
        reasons.append("css:display-none")
    if vis == "hidden":
        reasons.append("css:visibility-hidden")
    if op in {"0", "0.0"}:
        reasons.append("css:opacity-0")

    if fs and _ZERO_RE.match(fs):
        reasons.append("css:font-size-0")

    if pos in {"absolute", "fixed"} and (
        (left and _OFFSCREEN_RE.match(left)) or (top and _OFFSCREEN_RE.match(top))
    ):
        reasons.append("css:offscreen")

    if clip and _CLIP_ZERO_RE.match(clip):
        reasons.append("css:clip-zero")
    if clip_path and (
        _CLIP_PATH_INSET_HALF_RE.match(clip_path)
        or "clip-path: inset(50%)" in clip_path
    ):
        reasons.append("css:clip-path-inset-50")

    if width and _ZERO_RE.match(width):
        reasons.append("css:width-0")
    if height and _ZERO_RE.match(height):
        reasons.append("css:height-0")

    if col and (bg or col):
        if (bg and _WHITE_RE.match(bg) and _WHITE_RE.match(col)) or _TRANSPARENT_RE.match(
            col
        ):
            reasons.append("css:low-contrast")

    if text_indent:
        try:
            if _OFFSCREEN_RE.match(text_indent) or text_indent.strip().startswith(
                "-999"
            ):
                reasons.append("css:text-indent-offscreen")
        except Exception:
            pass

    return reasons


# -----------------------------
# Public API
# -----------------------------


def detect_hidden_text(html: str) -> Dict[str, object]:
    """
    Parse HTML and return:
        {"found": bool, "reasons": [...], "samples": [...]}

    - Uses lxml parser when available; falls back to 'html.parser'.
    - Considers attribute/class/style-based hiding.
    - Samples are stripped text content of hidden elements, capped to 5.
    """
    try:
        soup = BeautifulSoup(html or "", "lxml")
    except FeatureNotFound:
        soup = BeautifulSoup(html or "", "html.parser")

    reasons: List[str] = []
    samples: List[str] = []

    for el in soup.find_all(True):
        try:
            r = _is_hidden(el)
            if not r:
                continue
            txt = (el.get_text() or "").strip()
            if txt:
                samples.append(txt[:200])
            reasons.extend(r)
            if len(samples) >= 5:
                break
        except Exception:
            continue

    return {
        "found": bool(reasons and samples),
        "reasons": sorted(set(reasons))[:16],
        "samples": samples[:5],
    }

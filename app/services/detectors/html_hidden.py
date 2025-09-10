from __future__ import annotations

from bs4 import BeautifulSoup, FeatureNotFound
import re
from typing import Dict, List

_OFFSCREEN_RE = re.compile(r"^-?\d{3,}px$")
_ZERO_RE = re.compile(r"^0(?:px|em|rem|%)?$", re.I)
_WHITE_RE = re.compile(r"^(?:#?fff(?:fff)?|white)$", re.I)
_TRANSPARENT_RE = re.compile(r"^transparent$", re.I)


def _parse_style(style: str) -> Dict[str, str]:
    kv: Dict[str, str] = {}
    for part in (style or "").split(";"):
        if ":" in part:
            k, v = part.split(":", 1)
            kv[k.strip().lower()] = v.strip().lower()
    return kv


def _is_hidden(el) -> List[str]:
    reasons: List[str] = []
    if el.has_attr("hidden"):
        reasons.append("attr:hidden")
    if el.get("aria-hidden", "").lower() == "true":
        reasons.append("attr:aria-hidden")

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

    if disp == "none":
        reasons.append("css:display-none")
    if vis == "hidden":
        reasons.append("css:visibility-hidden")
    if op in {"0", "0.0"}:
        reasons.append("css:opacity-0")
    if fs and _ZERO_RE.match(fs):
        reasons.append("css:font-size-0")
    if pos in {"absolute", "fixed"} and ((left and _OFFSCREEN_RE.match(left)) or (top and _OFFSCREEN_RE.match(top))):
        reasons.append("css:offscreen")
    if col and bg and ((_WHITE_RE.search(col) and _WHITE_RE.search(bg)) or _TRANSPARENT_RE.search(col)):
        reasons.append("css:low-contrast")
    return reasons


def detect_hidden_text(html: str) -> Dict[str, object]:
    """
    Return {"found": bool, "reasons": [...], "samples": [...]}
    Prefer lxml; fall back to built-in html.parser if lxml unavailable.
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
        "reasons": sorted(set(reasons))[:8],
        "samples": samples[:5],
    }


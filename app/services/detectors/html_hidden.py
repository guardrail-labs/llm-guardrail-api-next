from __future__ import annotations

import re
from typing import Dict, List, Tuple, cast

# Lightweight HTML hidden-text detector used by ingress.
#
# Contract:
#   detect_hidden_text(html: str) -> {
#       "found": bool,
#       "reasons": List[str],    # canonical: style_hidden | white_on_white
#                                #            attr_hidden | class_hidden
#       "samples": List[str],    # short text contents near hidden spans
#   }
#
# Notes
# -----
# - We intentionally return the legacy reason keys expected by tests.
# - Prefer BeautifulSoup when available, but we ALWAYS run a regex fallback
#   pass as a backstop to catch simple inline style cases.

# ----------------------------- regex helpers ---------------------------------

_STYLE_HIDDEN_RE = re.compile(
    r"(?i)\b(display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?)"
)

_ZERO_RE = re.compile(r"(?i)^(0|0(?:\.0+)?|0px|0rem|0em)$")

# White color values (accept hex short/long, rgb/rgba, and keyword 'white')
# NOTE: Do NOT use VERBOSE ('x') here because of literal '#fff' tokens.
_WHITE_VALUE_RE = re.compile(
    r"(?i)\b("
    r"#fff(?:fff)?"
    r"|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\)"
    r"|rgba\(\s*255\s*,\s*255\s*,\s*255\s*,\s*1(?:\.0+)?\)"
    r"|white"
    r")\b"
)

_TRANSPARENT_RE = re.compile(r"(?i)\btransparent\b")

# Treat extreme offscreen positioning as effectively hidden
_OFFSCREEN_RE = re.compile(r"(?i)^-?\s*(?:1000|9999|\d{4,})px$")

# clip: rect(0 0 0 0) or clip-path: inset(50%)
_CLIP_ZERO_RE = re.compile(r"(?i)\bclip\s*:\s*rect\(\s*0(?:\s+0){3}\s*\)")
_CLIP_PATH_INSET_HALF_RE = re.compile(r"(?i)\bclip-path\s*:\s*inset\(\s*50%\s*\)")

# Popular utility classes for visually-hidden/hidden elements
_CLASS_HIDDEN = {
    "sr-only",
    "visually-hidden",
    "screen-reader-only",
    "screenreader-only",
    "sr_only",
    "u-hidden",
    "is-hidden",
    "hidden",
    "a11y-hidden",
    "offscreen",
    "clip",
}

# Fallback regexes (simple, conservative)
_FALLBACK_ATTR_HIDDEN_RE = re.compile(
    r"<[^>]+\s(hidden|aria-hidden=['\"]?true['\"]?)", re.I
)
_FALLBACK_CLASS_HIDDEN_RE = re.compile(
    r'class\s*=\s*["\'][^"\']*('
    r"sr-only|visually-hidden|screen-reader-only|u-hidden|is-hidden|hidden"
    r")[^\"']*[\"']",
    re.I,
)
_FALLBACK_WHITE_ON_WHITE_RE = re.compile(
    r"(?i)color\s*:\s*(#fff(?:fff)?|white)"
    r".*background(?:-color)?\s*:\s*(#fff(?:fff)?|white)"
)

# ----------------------------- utils -----------------------------------------


def _parse_style(style_str: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not style_str:
        return out
    for part in style_str.split(";"):
        if not part.strip():
            continue
        if ":" not in part:
            continue
        k, v = part.split(":", 1)
        out[k.strip().lower()] = v.strip().lower()
    return out


def _maybe_text_sample(el) -> str:
    try:
        # BeautifulSoup's get_text is dynamically typed; cast for mypy.
        txt = cast(str, el.get_text(strip=True))
        if txt:
            return txt[:200]
    except Exception:
        pass
    return ""


def _add_reason(reasons: List[str], samples: List[str], tag: str, sample: str) -> None:
    if tag not in reasons:
        reasons.append(tag)
    if sample and sample not in samples and len(samples) < 5:
        samples.append(sample)


# ----------------------------- core detection --------------------------------


def _element_hidden_reasons(el) -> List[str]:
    """Return canonical reason tags for a single element, no samples here."""
    reasons: List[str] = []

    # Attribute-based
    if getattr(el, "has_attr", lambda *_: False)("hidden"):
        reasons.append("attr_hidden")
    if str(el.get("aria-hidden", "")).lower() == "true":
        reasons.append("attr_hidden")

    # Class-based utilities
    classes = el.get("class", []) or []
    class_set = {str(c).strip().lower() for c in classes if str(c).strip()}
    if class_set & _CLASS_HIDDEN:
        reasons.append("class_hidden")

    # Inline style checks
    css = _parse_style(el.get("style", ""))

    disp = css.get("display")
    vis = css.get("visibility")
    op = css.get("opacity")
    fs = css.get("font-size")
    pos = css.get("position")
    left = css.get("left")
    top = css.get("top")
    color = css.get("color") or css.get("colour")
    bg = css.get("background-color") or css.get("background")

    # display:none / visibility:hidden / opacity:0 / font-size:0
    if disp == "none" or vis == "hidden" or (op in {"0", "0.0"}) or (fs and _ZERO_RE.match(fs)):
        reasons.append("style_hidden")

    # Offscreen patterns with absolute/fixed positioning
    if pos in {"absolute", "fixed"} and (
        (left and _OFFSCREEN_RE.match(left)) or (top and _OFFSCREEN_RE.match(top))
    ):
        reasons.append("style_hidden")

    # Clipping to zero / clip-path inset(50%)
    clip = css.get("clip")
    clip_path = css.get("clip-path")
    if clip and _CLIP_ZERO_RE.match(clip):
        reasons.append("style_hidden")
    if clip_path and _CLIP_PATH_INSET_HALF_RE.match(clip_path):
        reasons.append("style_hidden")

    # White text on white background (or transparent color)
    if color:
        is_white_fg = bool(_WHITE_VALUE_RE.search(color))
        is_transparent_fg = bool(_TRANSPARENT_RE.search(color))
    else:
        is_white_fg = False
        is_transparent_fg = False

    is_white_bg = bool(bg and _WHITE_VALUE_RE.search(bg))
    if (is_white_fg and is_white_bg) or is_transparent_fg:
        reasons.append("white_on_white")

    return reasons


def _collect_matches(rx: re.Pattern[str], html: str) -> List[str]:
    out: List[str] = []
    for m in rx.finditer(html):
        frag = html[max(0, m.start() - 40) : m.end() + 40]
        frag = re.sub(r"\s+", " ", frag)
        out.append(frag[:200])
        if len(out) >= 5:
            break
    return out


def _fallback_enrich(html: str, reasons: List[str], samples: List[str]) -> None:
    """
    Always-run regex fallback to ensure we catch simple inline patterns even
    if the soup-based path is unavailable or conservative.
    """
    if _FALLBACK_ATTR_HIDDEN_RE.search(html or ""):
        _add_reason(reasons, samples, "attr_hidden", "")

    if _FALLBACK_CLASS_HIDDEN_RE.search(html or ""):
        _add_reason(reasons, samples, "class_hidden", "")

    if _FALLBACK_WHITE_ON_WHITE_RE.search(html or ""):
        _add_reason(reasons, samples, "white_on_white", "")


def detect_hidden_text(html: str) -> Dict[str, object]:
    """
    Scan HTML for hidden or low-contrast text. Returns a dict with:
      - found: True if any canonical reasons were found
      - reasons: canonical reason strings (legacy-compatible)
      - samples: up to 5 short text samples
    """
    reasons: List[str] = []
    samples: List[str] = []

    # Fast path: global style patterns in raw HTML (ensures 'style_hidden' is surfaced)
    if _STYLE_HIDDEN_RE.search(html or ""):
        if "style_hidden" not in reasons:
            reasons.append("style_hidden")

    # Use BeautifulSoup if available for robust element-level checks.
    soup = None
    try:
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html or "", "html.parser")
    except Exception:
        soup = None

    if soup is not None:
        for el in soup.find_all(True):
            el_reasons = _element_hidden_reasons(el)
            if not el_reasons:
                continue
            sample = _maybe_text_sample(el)
            for r in el_reasons:
                _add_reason(reasons, samples, r, sample)

    # Always run fallback regex checks to bolster coverage.
    _fallback_enrich(html or "", reasons, samples)

    # If we still have no samples, try to produce something from raw matches.
    if not samples and reasons:
        samples.extend(_collect_matches(_STYLE_HIDDEN_RE, html or "")[:2])

    # Deduplicate with stable order
    seen: set[str] = set()
    uniq_reasons: List[str] = []
    for r in reasons:
        if r not in seen:
            uniq_reasons.append(r)
            seen.add(r)

    uniq_samples: List[str] = []
    for s in samples:
        if s and s not in uniq_samples:
            uniq_samples.append(s)
        if len(uniq_samples) >= 5:
            break

    return {
        "found": bool(uniq_reasons),
        "reasons": uniq_reasons,
        "samples": uniq_samples,
    }

from __future__ import annotations

import re
from typing import Dict, List, cast

# Lightweight HTML hidden-text detector used by ingress.
#
# Contract:
#   detect_hidden_text(html: str) -> {
#       "found": bool,
#       "reasons": List[str],    # canonical: style_hidden | white_on_white
#                                #            attr_hidden | class_hidden
#       "samples": List[str],    # short text contents near hidden spans
#   }

# ----------------------------- regex helpers ---------------------------------

_STYLE_HIDDEN_RE = re.compile(
    r"(?i)\b(display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?)"
)

_ZERO_RE = re.compile(r"(?i)^(0|0(?:\.0+)?|0px|0rem|0em)$")

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
    "sr-only-focusable",
    "u-visually-hidden",
    "vh",
    "a11y-visually-hidden",
    "offscreen",
    "clip",
}

# Fallback regexes (simple, conservative)
_FALLBACK_ATTR_HIDDEN_RE = re.compile(r"<[^>]+\s(hidden|aria-hidden=['\"]?true['\"]?)", re.I)
_FALLBACK_CLASS_HIDDEN_RE = re.compile(
    r'class\s*=\s*["\'][^"\']*('
    r"sr-only|sr-only-focusable|visually-hidden|u-visually-hidden|vh|"
    r"screen-reader-only|u-hidden|is-hidden|hidden|a11y-hidden|a11y-visually-hidden"
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


def _norm_css(val: str | None) -> str:
    return re.sub(r"\s+", "", (val or "").lower())


def _is_white_value(val: str | None) -> bool:
    raw = (val or "").strip().lower()
    v = _norm_css(val)
    if not raw and not v:
        return False
    if raw.startswith("#fff") or v.startswith("#fff"):
        return True
    if raw.startswith("white") or v == "white":
        return True
    if v == "rgb(255,255,255)":
        return True
    if v in {"rgba(255,255,255,1)", "rgba(255,255,255,1.0)"}:
        return True
    return False


def _is_transparent_value(val: str | None) -> bool:
    return bool(_TRANSPARENT_RE.search(val or ""))


def _maybe_text_sample(el) -> str:
    try:
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
    z = css.get("z-index")
    lh = css.get("line-height")
    text_indent = css.get("text-indent")

    if color and color.startswith("var(") and color.endswith(")"):
        var_name = color[4:-1].strip()
        if var_name.startswith("--"):
            resolved = css.get(var_name)
            if resolved:
                color = resolved

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

    if text_indent and _OFFSCREEN_RE.match(text_indent):
        reasons.append("style_hidden")

    if lh and _ZERO_RE.match(lh):
        reasons.append("style_hidden")

    if pos in {"absolute", "fixed"} and z == "-1":
        reasons.append("style_hidden")

    # White text on white background (or transparent color)
    is_white_fg = _is_white_value(color)
    is_transparent_fg = _is_transparent_value(color)
    is_white_bg = _is_white_value(bg)
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

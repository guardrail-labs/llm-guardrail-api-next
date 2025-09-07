from __future__ import annotations

import re
from typing import Dict, List, Tuple

# Very small, dependency-free detector for likely "invisible" text in PDFs.
# We scan content streams for:
#  - White non-stroking color (1 1 1 rg)
#  - Invisible or clipping text render mode (3 Tr or 7 Tr)
#  - Tiny font sizes (near-zero Tf)
# Then we try to extract nearby text shown via Tj (literal or hex form).
#
# This is intentionally heuristic and conservative to keep it lightweight.
# It’s enough to surface attacker-intended hidden strings so our redactors
# and rules can see them, without pulling in heavy PDF parsing deps.

# Uncompressed content streams
_STREAM_RE = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.S)

# White fill (non-stroking) color
_WHITE_RE = re.compile(rb"\b1(?:\.0+)?\s+1(?:\.0+)?\s+1(?:\.0+)?\s+rg\b")

# Text render mode: 3 = invisible text; 7 = clip
_INVISIBLE_TR_RE = re.compile(rb"\b(?:3|7)\s+Tr\b")

# Tiny font (very small): "0 Tf" or "0.xx Tf"
_TINY_FONT_RE = re.compile(rb"\b(?:0(?:\.\d+)?|0\.\d{1,2})\s+Tf\b")

# Text showing operators (literal or hex)
_TEXT_SHOW_RE = re.compile(rb"\((.*?)\)\s*Tj|<([0-9A-Fa-f\s]+)>\s*Tj", re.S)


def _decode_literal(b: bytes) -> str:
    try:
        # Latin-1 is crude but stable for byte-preserving decode
        return b.decode("latin-1", errors="ignore")
    except Exception:
        return ""


def _decode_hex(h: bytes) -> str:
    try:
        compact = b"".join(h.split())
        raw = bytes.fromhex(compact.decode("ascii", errors="ignore"))
        return raw.decode("latin-1", errors="ignore")
    except Exception:
        return ""


def _extract_text_near(mark: re.Pattern[bytes], block: bytes, max_items: int = 3) -> List[str]:
    """Look around each match of `mark` for nearby Tj text; return a few samples."""
    out: List[str] = []
    for m in mark.finditer(block):
        start = max(0, m.start() - 400)
        end = min(len(block), m.end() + 400)
        window = block[start:end]
        for tj in _TEXT_SHOW_RE.finditer(window):
            if tj.group(1):
                s = _decode_literal(tj.group(1))
            elif tj.group(2):
                s = _decode_hex(tj.group(2))
            else:
                continue
            s = s.strip()
            if s:
                out.append(s[:200])
                if len(out) >= max_items:
                    return out
    return out


def detect_hidden_text(pdf_bytes: bytes) -> Dict[str, object]:
    """
    Return {"found": bool, "reasons": [..], "samples": [..]}.
    Reasons are tags like "white_nonstroke_color" or "invisible_render_mode".
    Samples are short decoded strings near suspicious drawing ops.
    """
    reasons: List[str] = []
    samples: List[str] = []

    for sm in _STREAM_RE.finditer(pdf_bytes):
        block = sm.group(1)

        if _WHITE_RE.search(block):
            reasons.append("white_nonstroke_color")
            samples.extend(_extract_text_near(_WHITE_RE, block))

        if _INVISIBLE_TR_RE.search(block):
            reasons.append("invisible_render_mode")
            samples.extend(_extract_text_near(_INVISIBLE_TR_RE, block))

        if _TINY_FONT_RE.search(block):
            reasons.append("tiny_font")
            samples.extend(_extract_text_near(_TINY_FONT_RE, block))

        if len(samples) >= 5:
            break

    # Dedupe and trim
    reasons = sorted(set(reasons))
    uniq: List[str] = []
    for s in samples:
        if s not in uniq:
            uniq.append(s)
        if len(uniq) >= 5:
            break

    return {"found": bool(reasons and uniq), "reasons": reasons, "samples": uniq}


# ---------------------------------------------------------------------------
# Legacy sanitizer for unit tests and ingress pipeline (simple marker-based).


def _extract_text(pdf_bytes: bytes) -> Tuple[List[str], List[str]]:
    """Mock extractor that separates visible and hidden text using markers."""
    text = pdf_bytes.decode("utf-8", errors="ignore")
    visible: List[str] = []
    hidden: List[str] = []
    for line in text.splitlines():
        if line.startswith("VISIBLE:"):
            visible.append(line[len("VISIBLE:") :])
        elif line.startswith("HIDDEN:"):
            hidden.append(line[len("HIDDEN:") :])
    return visible, hidden


def sanitize_for_downstream(pdf_bytes: bytes):
    """Return visible text and rule hits for hidden spans (legacy)."""
    visible, hidden = _extract_text(pdf_bytes)
    rule_hits = []
    if hidden:
        rule_hits.append({"tag": "inj:hidden_text_pdf", "pattern": "hidden_pdf_text"})
    debug = {"spans_count": len(hidden), "samples": hidden[:2]}
    return "\n".join(visible), rule_hits, debug

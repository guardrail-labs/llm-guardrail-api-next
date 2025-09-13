from __future__ import annotations

import io
from typing import Dict, List

from docx import Document


def _is_hidden_run(run) -> List[str]:
    reasons: List[str] = []
    try:
        if getattr(run.font, "hidden", None):
            reasons.append("w:vanish")
    except Exception:
        pass
    try:
        if run.font.color and run.font.color.rgb and str(run.font.color.rgb).lower() in {
            "ffffff"
        }:
            reasons.append("font:white")
    except Exception:
        pass
    try:
        if run.font.size and getattr(run.font.size, "pt", None) == 0:
            reasons.append("font:size-0")
    except Exception:
        pass
    return reasons


def detect_hidden_text(docx_bytes: bytes) -> Dict[str, object]:
    """
    Return {"found": bool, "reasons": [...], "samples": [...]}
    IMPORTANT: python-docx expects a file-like; wrap bytes in BytesIO.
    """
    reasons: List[str] = []
    samples: List[str] = []

    doc = Document(io.BytesIO(docx_bytes))
    for p in doc.paragraphs:
        for r in p.runs:
            rs = _is_hidden_run(r)
            if not rs:
                continue
            t = (r.text or "").strip()
            if t:
                samples.append(t[:200])
            reasons.extend(rs)
            if len(samples) >= 5:
                return {
                    "found": True,
                    "reasons": sorted(set(reasons))[:8],
                    "samples": samples[:5],
                }

    return {
        "found": bool(reasons and samples),
        "reasons": sorted(set(reasons))[:8],
        "samples": samples[:5],
    }

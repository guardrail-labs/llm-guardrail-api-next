from __future__ import annotations

import os
import re
from typing import Dict, Tuple

_PRINTABLE_RE = re.compile(rb"[ -~]{4,}")  # ASCII printable, min length 4


def _extract_printable_strings(
    data: bytes, max_total: int = 20000
) -> str:
    """
    Safe binary->text heuristic:
    - Pull ASCII-printable runs (>=4 chars)
    - Join with spaces
    - Truncate at max_total
    """
    if not data:
        return ""
    chunks = _PRINTABLE_RE.findall(data)
    text = b" ".join(chunks).decode("utf-8", "ignore")
    if len(text) > max_total:
        return text[:max_total]
    return text


def _ext(filename: str) -> str:
    return os.path.splitext(filename.lower())[1]


def extract_from_bytes(
    filename: str, content_type: str, data: bytes
) -> Tuple[str, Dict[str, int | str]]:
    """
    Returns (extracted_text, meta). No external deps; never executes content.
    Strategy:
      - text/* : decode as UTF-8
      - application/json : decode as UTF-8
      - application/pdf : printable string scan
      - image/*, audio/*, others : printable string scan (best-effort)
    """
    ctype = (content_type or "").lower()
    ext = _ext(filename)
    text = ""

    if ctype.startswith("text/") or ctype == "application/json":
        text = data.decode("utf-8", "ignore")
        extractor = "text"
    elif ctype == "application/pdf" or ext == ".pdf":
        text = _extract_printable_strings(data)
        extractor = "pdf_printable"
    elif ctype.startswith("image/"):
        text = _extract_printable_strings(data)
        extractor = "image_printable"
    elif ctype.startswith("audio/"):
        # No ASR by default; only printable runs for safety
        text = _extract_printable_strings(data)
        extractor = "audio_printable"
    else:
        text = _extract_printable_strings(data)
        extractor = "generic_printable"

    meta: Dict[str, int | str] = {
        "filename": filename,
        "media_type": ctype or "unknown",
        "bytes": len(data),
        "extractor": extractor,
        "extracted_chars": len(text),
    }
    return text, meta

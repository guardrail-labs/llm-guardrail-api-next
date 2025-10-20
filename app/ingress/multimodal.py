from __future__ import annotations

import base64
import io
import re
from typing import Optional

try:  # PDF text (no images) via pdfminer.six
    from pdfminer.high_level import extract_text as _pdf_text
except Exception:  # pragma: no cover
    _pdf_text = None

try:  # Image OCR via pytesseract + pillow
    import pytesseract
    from PIL import Image
except Exception:  # pragma: no cover
    Image = None
    pytesseract = None


_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bignore (all )?previous instructions\b", re.I),
    re.compile(r"\boverride (the )?system prompt\b", re.I),
    re.compile(r"\bdisregard (the )?rules\b", re.I),
    re.compile(r"\bas (system|developer) role\b", re.I),
    re.compile(r"\bdo not sanitize\b", re.I),
]

_IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tiff")


def pdf_supported() -> bool:
    return _pdf_text is not None


def image_supported() -> bool:
    return Image is not None and pytesseract is not None


def detect_injection(text: str) -> int:
    """Return number of injection pattern hits in text."""
    hits = 0
    for pat in _INJECTION_PATTERNS:
        if pat.search(text):
            hits += 1
    return hits


def extract_from_pdf(raw: bytes) -> str:
    """Best-effort PDF text extraction; empty string if unsupported."""
    if not pdf_supported():
        return ""
    try:
        buf = io.BytesIO(raw)
        text = _pdf_text(buf) or ""
        return text
    except Exception:
        return ""


def extract_from_image(raw: bytes) -> str:
    """Best-effort OCR for images; empty string if unsupported."""
    if not image_supported():
        return ""
    try:
        img = Image.open(io.BytesIO(raw))
        text = pytesseract.image_to_string(img) or ""
        return text
    except Exception:
        return ""


def extract_from_base64_image(b64: str) -> str:
    """Decode and OCR base64 image strings (data URI or raw b64)."""
    try:
        if b64.startswith("data:"):
            _, _, tail = b64.partition(",")
            raw = base64.b64decode(tail)
        else:
            raw = base64.b64decode(b64)
        return extract_from_image(raw)
    except Exception:
        return ""


def sniff_mime(filename: Optional[str], content_type: Optional[str]) -> str:
    """Return coarse mime family: 'pdf'|'image'|'other'."""
    ct = (content_type or "").lower()
    if "pdf" in ct:
        return "pdf"
    if "image/" in ct:
        return "image"
    if filename:
        lowered = filename.lower()
        if lowered.endswith(".pdf"):
            return "pdf"
        if lowered.endswith(_IMAGE_EXTS):
            return "image"
    return "other"


def estimate_base64_size(b64: str) -> int:
    """Estimate decoded size of a base64 string (data URI aware)."""
    try:
        payload = b64.split(",", 1)[1] if b64.startswith("data:") else b64
        stripped = payload.strip()
        padding = stripped.count("=")
        length = len(stripped)
        size = (length * 3) // 4 - padding
        return max(size, 0)
    except Exception:
        return 0

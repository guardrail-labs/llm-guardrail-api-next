from __future__ import annotations

import io
import os
import time
from typing import Tuple

# Optional imports; we degrade gracefully if not installed
try:
    from PIL import Image
except Exception:  # pragma: no cover
    Image = None

try:
    import pytesseract
except Exception:  # pragma: no cover
    pytesseract = None

try:
    from pdfminer.high_level import extract_text as pdf_extract_text
except Exception:  # pragma: no cover
    pdf_extract_text = None


def _truthy(val: object) -> bool:
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


def ocr_enabled() -> bool:
    return _truthy(os.environ.get("OCR_ENABLED", "0"))


def _now_ms() -> int:
    return int(time.time() * 1000)


def _deadline_ms() -> int:
    try:
        return int(os.environ.get("OCR_TIMEOUT_MS", "3000"))
    except Exception:
        return 3000


def extract_from_image(raw_bytes: bytes) -> str:
    """
    OCR a single image. If deps are missing, return empty string.
    """
    if not (Image and pytesseract and raw_bytes):
        return ""
    try:
        img = Image.open(io.BytesIO(raw_bytes))
        return pytesseract.image_to_string(img) or ""
    except Exception:
        return ""


def extract_from_pdf(raw_bytes: bytes) -> Tuple[str, bool]:
    """
    Extract text from a PDF using the text layer first (captures hidden/white text).
    Returns (text, used_textlayer: bool). If pdfminer is unavailable or fails, returns ("", False).
    """
    if not (pdf_extract_text and raw_bytes):
        return ("", False)
    try:
        text = pdf_extract_text(io.BytesIO(raw_bytes)) or ""
        return (text, True)
    except Exception:
        return ("", False)


def extract_pdf_with_optional_ocr(raw_bytes: bytes) -> Tuple[str, str]:
    """
    PDF pipeline:
      1) Try text layer (pdfminer) -> outcome 'textlayer' if any text found.
      2) If empty/short and OCR_PDF_FALLBACK=1, best-effort image OCR ->
         outcome 'fallback' if non-empty.
      3) Else -> outcome 'empty'.
    Returns (text, outcome).
    """
    text, used_layer = extract_from_pdf(raw_bytes)
    if text and len(text.strip()) > 0:
        return (text, "textlayer")

    if not _truthy(os.environ.get("OCR_PDF_FALLBACK", "0")):
        return (text or "", "empty")

    # Optional fallback OCR via PIL+pytesseract if the PDF happens to be image-like.
    if not (Image and pytesseract):
        return (text or "", "empty")

    start = _now_ms()
    if _now_ms() - start > _deadline_ms():
        return (text or "", "empty")

    try:
        img = Image.open(io.BytesIO(raw_bytes))
        ocr_txt = pytesseract.image_to_string(img) or ""
        if ocr_txt.strip():
            return (ocr_txt, "fallback")
        return (text or "", "empty")
    except Exception:
        return (text or "", "empty")


"""
Ingress helpers for PDF/DOCX/Image preprocessing.

- PDF: optionally sanitize hidden/transparent text (detector is optional).
- DOCX: detect jailbreak/social-engineering lines and sanitize.
- Image: safe-transform, mark as non-interpretable, optional re-encode.

Each function returns a small dict suitable for downstream ingress evaluation:
  * PDF  -> {"text", "rule_hits", "debug"}
  * DOCX -> {"text", "rule_hits", "debug"}
  * IMG  -> {"image_bytes", "rule_hits", "debug"}

All functions include a `debug.sources` array with per-source breadcrumbs.
"""

from __future__ import annotations

import os
from typing import Any, Callable, Dict, List, Optional, Tuple, cast

from app.services import runtime_flags
from app.services.detectors.docx_jb import (
    DocxExtractor,
    detect_and_sanitize_docx,
)
from app.services.media.safe_image import (
    ImageReencoder,
    safe_transform,
)

# Callable signature returned by the PDF sanitizer:
#   (sanitized_visible_text, rule_hits, debug)
PdfSanitizer = Callable[[bytes], Tuple[str, List[str], Dict[str, Any]]]

# --- Optional import of the PDF sanitizer implementation ---------------------
# The detector re-exports `pdf_sanitize_for_downstream` from
# `app.services.detectors.__init__`. If it is not available, we fall back
# gracefully without raising import errors or confusing mypy.


def _load_pdf_sanitizer() -> Optional[PdfSanitizer]:
    try:
        from app.services.detectors import (
            pdf_sanitize_for_downstream as _impl,
        )
    except Exception:
        return None
    return cast(PdfSanitizer, _impl)


_pdf_sanitize: Optional[PdfSanitizer] = _load_pdf_sanitizer()

# Feature flags (default ON) ---------------------------------------------------


_FLAG_MAP = {
    "PDF_DETECTOR_ENABLED": "pdf_detector_enabled",
    "DOCX_DETECTOR_ENABLED": "docx_detector_enabled",
    "IMAGE_SAFE_TRANSFORM_ENABLED": "image_safe_transform_enabled",
}


def _enabled(env: str, default: bool = True) -> bool:
    name = _FLAG_MAP.get(env)
    if name:
        return bool(runtime_flags.get(name))
    raw = os.getenv(env)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


# ---------------- PDF ---------------------------------------------------------


def process_pdf_ingress(pdf_bytes: bytes) -> Dict[str, Any]:
    """
    Extract safe, visible-only text from a PDF for ingress evaluation.
    Includes debug.sources entry with detector availability/enabled flags.
    """
    sources: List[Dict[str, Any]] = []
    enabled = _enabled("PDF_DETECTOR_ENABLED", True)

    if enabled and _pdf_sanitize is not None:
        text, rule_hits, debug = _pdf_sanitize(pdf_bytes)
        sources.append(
            {
                "type": "pdf",
                "enabled": True,
                "available": True,
                "rule_hits": rule_hits,
                "meta": {"spans_count": debug.get("spans_count", 0)},
            }
        )
        return {
            "text": text,
            "rule_hits": rule_hits,
            "debug": {"pdf_hidden": debug, "sources": sources},
        }

    # Fallback: detector disabled or not available
    sources.append(
        {
            "type": "pdf",
            "enabled": enabled,
            "available": _pdf_sanitize is not None,
            "rule_hits": [],
            "meta": {"spans_count": 0},
        }
    )
    return {
        "text": "",
        "rule_hits": [],
        "debug": {
            "pdf_hidden": {
                "spans_count": 0,
                "detector_enabled": enabled,
                "available": _pdf_sanitize is not None,
            },
            "sources": sources,
        },
    }


# ---------------- DOCX --------------------------------------------------------


def process_docx_ingress(
    docx_bytes: bytes, extractor: Optional[DocxExtractor] = None
) -> Dict[str, Any]:
    """
    Scan a DOCX for jailbreak/social-engineering prompts and return sanitized text.
    Accepts an optional extractor (useful for tests); when disabled, returns empty text.
    """
    sources: List[Dict[str, Any]] = []
    enabled = _enabled("DOCX_DETECTOR_ENABLED", True)
    if enabled:
        res = detect_and_sanitize_docx(docx_bytes, extractor=extractor)
        sources.append(
            {
                "type": "docx",
                "enabled": True,
                "available": True,
                "rule_hits": res.rule_hits,
                "meta": {
                    "kept_count": res.debug.get("kept_count", 0),
                    "lines_scanned": res.debug.get("lines_scanned", 0),
                },
            }
        )
        return {
            "text": res.sanitized_text,
            "rule_hits": res.rule_hits,
            "debug": {"docx": res.debug, "sources": sources},
        }

    sources.append(
        {"type": "docx", "enabled": False, "available": True, "rule_hits": [], "meta": {}}
    )
    return {"text": "", "rule_hits": [], "debug": {"docx": {}, "sources": sources}}


# ---------------- Image -------------------------------------------------------


def process_image_ingress(
    image_bytes: bytes, reencoder: Optional[ImageReencoder] = None
) -> Dict[str, Any]:
    """
    Safe-transform an image and mark it as non-interpretable for instruction purposes.
    Returns the (possibly) re-encoded bytes so downstream can continue.
    """
    sources: List[Dict[str, Any]] = []
    enabled = _enabled("IMAGE_SAFE_TRANSFORM_ENABLED", True)
    if enabled:
        res = safe_transform(image_bytes, reencoder=reencoder)
        sources.append(
            {
                "type": "image",
                "enabled": True,
                "available": True,
                "rule_hits": res.rule_hits,
                "meta": {
                    "reencoded": res.debug.get("reencoded", False),
                    "input_size": res.debug.get("input_size", 0),
                    "output_size": res.debug.get("output_size", 0),
                },
            }
        )
        return {
            "image_bytes": res.image_bytes,
            "rule_hits": res.rule_hits,
            "debug": {"image": res.debug, "sources": sources},
        }

    # Disabled: pass-through, but still communicate intent via sources.
    sources.append(
        {"type": "image", "enabled": False, "available": True, "rule_hits": [], "meta": {}}
    )
    return {
        "image_bytes": image_bytes,
        "rule_hits": [],
        "debug": {"image": {"reencoded": False}, "sources": sources},
    }

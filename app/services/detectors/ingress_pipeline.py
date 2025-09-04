# app/services/detectors/ingress_pipeline.py
"""
Ingress helpers for PDF preprocessing.

- Optionally sanitize PDFs by stripping hidden/transparent text.
- Safe defaults when the detector is unavailable or disabled.

This module is import- and type-safe for mypy and Ruff.
"""

from __future__ import annotations

import os
from typing import Any, Callable, Dict, List, Optional, Tuple, cast

# Callable signature returned by the PDF sanitizer:
#   (sanitized_visible_text, rule_hits, debug)
PdfSanitizer = Callable[[bytes], Tuple[str, List[str], Dict[str, Any]]]

# --- Optional import of the PDF sanitizer implementation ---------------------
# The detector re-exports `pdf_sanitize_for_downstream` from
# `app.services.detectors.__init__`. If it is not available, we fall back
# gracefully without raising import errors or confusing mypy.
try:
    from app.services.detectors import (
        pdf_sanitize_for_downstream as _pdf_sanitize_impl,
    )
except Exception:
    _pdf_sanitize_impl = None  # falls back cleanly

# Tell mypy the exact optional callable type of the imported symbol.
_pdf_sanitize: Optional[PdfSanitizer] = cast(
    Optional[PdfSanitizer], _pdf_sanitize_impl
)

# Feature flag (defaults ON). Lets ops disable detector without code changes.
_PDF_DETECTOR_ENABLED = os.getenv("PDF_DETECTOR_ENABLED", "true").lower() in (
    "1",
    "true",
    "yes",
    "on",
)


def process_pdf_ingress(pdf_bytes: bytes) -> Dict[str, Any]:
    """
    Extract safe, visible-only text from a PDF for ingress evaluation.
    If the detector is disabled or unavailable, return an empty text with
    informative debug breadcrumbs (no exceptions).
    """
    if _PDF_DETECTOR_ENABLED and _pdf_sanitize is not None:
        text, rule_hits, debug = _pdf_sanitize(pdf_bytes)
        return {
            "text": text,
            "rule_hits": rule_hits,
            "debug": {"pdf_hidden": debug},
        }

    # Fallback: detector disabled or not available
    return {
        "text": "",
        "rule_hits": [],
        "debug": {
            "pdf_hidden": {
                "spans_count": 0,
                "detector_enabled": _PDF_DETECTOR_ENABLED,
                "available": _pdf_sanitize is not None,
            }
        },
    }

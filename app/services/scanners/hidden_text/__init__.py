from __future__ import annotations

from typing import List

from app.settings import HIDDEN_TEXT_SCAN, HIDDEN_TEXT_SCAN_MAX_BYTES
from app.telemetry.metrics import add_hidden_text_bytes, inc_hidden_text

from .docx import scan_docx_for_hidden
from .html import scan_html_for_hidden
from .policy import decide_for_hidden_reasons as decide_for_hidden_reasons


def scan_and_record_html(html: str) -> List[str]:
    if not HIDDEN_TEXT_SCAN:
        return []
    b = (html or "").encode("utf-8")
    if HIDDEN_TEXT_SCAN_MAX_BYTES and len(b) > HIDDEN_TEXT_SCAN_MAX_BYTES:
        return []
    reasons = scan_html_for_hidden(html)
    if reasons:
        add_hidden_text_bytes("html", len(b))
        for r in reasons:
            inc_hidden_text("html", r)
    return reasons


def scan_and_record_docx(buf: bytes) -> List[str]:
    if not HIDDEN_TEXT_SCAN or not buf:
        return []
    if HIDDEN_TEXT_SCAN_MAX_BYTES and len(buf) > HIDDEN_TEXT_SCAN_MAX_BYTES:
        return []
    reasons = scan_docx_for_hidden(buf)
    if reasons:
        add_hidden_text_bytes("docx", len(buf))
        for r in reasons:
            inc_hidden_text("docx", r)
    return reasons

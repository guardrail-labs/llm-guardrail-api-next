# app/redaction.py
from __future__ import annotations

import re
from typing import Any

# Simple, case-insensitive email pattern good enough for tests and common inputs
_EMAIL_RE = re.compile(
    r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"
)

def redact_text(text: Any) -> str:
    """
    Redact sensitive tokens in text for OpenAI-compat endpoints.

    Current behavior:
      - Redact email addresses -> "[REDACTED:EMAIL]"

    Notes:
      - Accepts any input, coerces to str.
      - Keeps other content unchanged to avoid surprising outputs.
    """
    s = text if isinstance(text, str) else str(text)
    s = _EMAIL_RE.sub("[REDACTED:EMAIL]", s)
    return s

__all__ = ["redact_text"]

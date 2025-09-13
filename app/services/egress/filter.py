from __future__ import annotations

import re
from typing import Any, Tuple

Redaction = Tuple[re.Pattern[str], str]

DEFAULT_REDACTIONS: Tuple[Redaction, ...] = (
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED-SSN]"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[REDACTED-EMAIL]"),
)


def _apply_redactions_text(text: str, redactions: Tuple[Redaction, ...]) -> str:
    out = text
    for pat, repl in redactions:
        out = pat.sub(repl, out)
    return out


def _transform(obj: Any, redactions: Tuple[Redaction, ...]) -> Any:
    if obj is None:
        return None
    if isinstance(obj, str):
        return _apply_redactions_text(obj, redactions)
    if isinstance(obj, dict):
        return {k: _transform(v, redactions) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_transform(v, redactions) for v in obj]
    return obj


def transform(obj: Any) -> Any:
    """Backward-compatible redaction using built-in defaults only."""
    return _transform(obj, DEFAULT_REDACTIONS)


def transform_with(obj: Any, redactions: Tuple[Redaction, ...]) -> Any:
    """Redaction with a supplied redaction set."""
    return _transform(obj, redactions)

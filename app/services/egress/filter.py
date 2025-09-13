from __future__ import annotations

import re
from typing import Any, Tuple

Redaction = Tuple[re.Pattern[str], str]

DEFAULT_REDACTIONS: Tuple[Redaction, ...] = (
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED-SSN]"),
    (
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "[REDACTED-EMAIL]",
    ),
)

def apply_redactions_text(
    text: str, redactions: Tuple[Redaction, ...] = DEFAULT_REDACTIONS
) -> str:
    out = text
    for pat, repl in redactions:
        out = pat.sub(repl, out)
    return out

def transform(obj: Any) -> Any:
    if obj is None:
        return None
    if isinstance(obj, str):
        return apply_redactions_text(obj)
    if isinstance(obj, dict):
        return {k: transform(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [transform(v) for v in obj]
    return obj

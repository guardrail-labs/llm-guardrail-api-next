from __future__ import annotations

import re
from re import Match
from typing import Any, Dict

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_SSN = re.compile(r"\b(?!000|666)(?:[0-8]\d{2})[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b")
_PHONE = re.compile(r"\b\+?1?[-. (]?\d{3}[-. )]?\d{3}[-. ]?\d{4}\b")
_SECRET_KEYS = (
    "api_key",
    "apikey",
    "authorization",
    "token",
    "secret",
    "password",
)


def _mask(_val: Match[str] | str) -> str:
    return "[REDACTED]"


def redact_string(val: str) -> str:
    out = _EMAIL.sub(_mask, val)
    out = _SSN.sub(_mask, out)
    out = _PHONE.sub(_mask, out)
    return out


def redact_obj(obj: Any) -> Any:
    if isinstance(obj, str):
        return redact_string(obj)
    if isinstance(obj, list):
        return [redact_obj(item) for item in obj]
    if isinstance(obj, dict):
        clean: Dict[str, Any] = {}
        for key, value in obj.items():
            lowered = str(key).lower()
            if lowered in _SECRET_KEYS:
                clean[key] = _mask(str(value))
            else:
                clean[key] = redact_obj(value)
        return clean
    return obj

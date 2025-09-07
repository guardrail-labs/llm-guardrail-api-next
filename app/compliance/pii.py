from __future__ import annotations

import hashlib
import re
from typing import Dict, Tuple

from app.config import get_settings

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"(?:\+?\d{1,3}[\s\-\.]?)?(?:\(?\d{3}\)?[\s\-\.]?)\d{3}[\s\-\.]?\d{4}")


def _salted_hash(value: str, salt: str, algo: str) -> str:
    if algo.lower() != "sha256":
        algo = "sha256"
    h = hashlib.sha256()
    h.update(salt.encode("utf-8"))
    h.update(b":")
    h.update(value.strip().lower().encode("utf-8"))
    return h.hexdigest()


def hash_email(email: str) -> str:
    s = get_settings()
    return _salted_hash(email, s.PII_SALT, s.PII_HASH_ALGO)


def hash_phone(phone: str) -> str:
    s = get_settings()
    return _salted_hash(phone, s.PII_SALT, s.PII_HASH_ALGO)


def redact_and_hash(text: str) -> Tuple[str, Dict[str, int]]:
    """
    Replace emails/phones with hashed tokens. Returns (sanitized_text, counters).
    Counters include families like 'pii:email' and 'pii:phone'.
    """
    if not text:
        return text, {}

    s = get_settings()
    counters: Dict[str, int] = {}
    out = text

    if s.PII_EMAIL_HASH_ENABLED:
        emails = list(_EMAIL_RE.finditer(out))
        if emails:
            counters["pii:email"] = counters.get("pii:email", 0) + len(emails)
            for m in reversed(emails):
                token = f"[EMAIL:{hash_email(m.group(0))[:12]}]"
                start, end = m.span()
                out = out[:start] + token + out[end:]

    if s.PII_PHONE_HASH_ENABLED:
        phones = list(_PHONE_RE.finditer(out))
        if phones:
            counters["pii:phone"] = counters.get("pii:phone", 0) + len(phones)
            for m in reversed(phones):
                token = f"[PHONE:{hash_phone(m.group(0))[:12]}]"
                start, end = m.span()
                out = out[:start] + token + out[end:]

    return out, counters

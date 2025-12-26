from __future__ import annotations

import hashlib
import re
import string

_PUNCT_RE = re.compile(f"[{re.escape(string.punctuation)}]")
_WS_RE = re.compile(r"\s+")
_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{16}$")


def _canonical_form(text: str) -> str:
    normalized = (text or "").lower()
    normalized = _PUNCT_RE.sub(" ", normalized)
    normalized = _WS_RE.sub(" ", normalized).strip()
    return normalized


def fingerprint_prompt(text: str) -> str:
    canonical = _canonical_form(text)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return digest[:16]


def _looks_like_fingerprint(text: str) -> bool:
    return bool(_FINGERPRINT_RE.match(text or ""))


def is_near_duplicate(prev: str, curr: str) -> bool:
    if _looks_like_fingerprint(prev) and _looks_like_fingerprint(curr):
        return prev == curr
    if _looks_like_fingerprint(prev):
        return prev == fingerprint_prompt(curr)
    if _looks_like_fingerprint(curr):
        return curr == fingerprint_prompt(prev)
    return _canonical_form(prev) == _canonical_form(curr)


__all__ = ["fingerprint_prompt", "is_near_duplicate"]

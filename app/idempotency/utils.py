"""Utility helpers shared across idempotency components."""

from __future__ import annotations

import hashlib
import os

_LOG_PII_OK_VALUES = {"1", "true", "yes", "on"}


def mask_idempotency_key(key: str) -> str:
    """Return a log-safe representation of ``key``.

    Unless ``LOG_PII_OK`` explicitly opts-in, the idempotency key is replaced
    with a short SHA-256 prefix so operators can correlate entries without
    leaking raw identifiers into logs.
    """

    raw = os.environ.get("LOG_PII_OK", "").strip().lower()
    if raw in _LOG_PII_OK_VALUES:
        return key
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return f"hash:{digest[:16]}"


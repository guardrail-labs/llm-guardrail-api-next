"""Utilities for idempotency logging and masking."""
from __future__ import annotations

import hashlib
import json
import logging
import os
from typing import Any

_LOG = logging.getLogger("app.idempotency")


def mask_idempotency_key(key: str) -> str:
    """Return masked representation unless LOG_PII_OK allows raw logging."""
    if not key:
        return ""
    if os.getenv("LOG_PII_OK", "").strip().lower() in {"1", "true", "yes", "on"}:
        return key
    digest = hashlib.sha256(key.encode("utf-8", "ignore")).hexdigest()
    return digest[:10]


def log_idempotency_event(event: str, *, key: str, tenant: str, **fields: Any) -> None:
    payload = {
        "event": event,
        "tenant": tenant,
        "idempotency_key_masked": mask_idempotency_key(key),
    }
    for name, value in fields.items():
        if value is not None:
            payload[name] = value
    try:
        _LOG.info("idempotency_event %s", json.dumps(payload, sort_keys=True))
    except Exception:
        _LOG.debug("idempotency logging failed", exc_info=True)

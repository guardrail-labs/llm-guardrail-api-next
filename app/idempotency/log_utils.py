"""Structured logging helpers for idempotency events.

Guarantees:
- Never log the full idempotency key; only a masked prefix.
- Optional PII logging toggle via env IDEMP_LOG_INCLUDE_PII (default: 0 / disabled).
- Preserve core operational fields used by dashboards & runbooks.

Fields we keep (non-PII):
- tenant, role, state, replay_count, fp_prefix, wait_ms (when provided)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from typing import Any, Dict, Mapping, Optional, Tuple

from app import settings as settings_module

_LOG = logging.getLogger("app.idempotency")


# ---- helpers -----------------------------------------------------------------


def _mask_key(val: Optional[str], prefix_len: int) -> Optional[str]:
    """
    Return a masked representation of an idempotency key.

    Rules:
    - If val is falsy, return it unchanged.
    - Never reveal the full key, even for very short keys.
    - Show at most `visible_len` chars, where visible_len <= len(val) - 1.
    - Append an 8-char SHA-256 tail to provide stable, non-reversible context.
    - Always include a single unicode ellipsis to signal truncation.
    """
    if not val:
        return val

    try:
        pl = int(prefix_len)
    except Exception:
        # Defensive: treat bad inputs as zero to avoid revealing extra chars.
        pl = 0

    # Ensure at least one character of the original is always withheld.
    visible_len = min(max(pl, 0), max(len(val) - 1, 0))
    prefix = val[:visible_len]

    base = val.encode("utf-8")
    candidate = ""
    for salt in range(256):
        payload = base if salt == 0 else base + f":{salt}".encode("utf-8")
        digest = hashlib.sha256(payload).hexdigest()
        for start in range(0, len(digest) - 8 + 1):
            tail = digest[start : start + 8]
            candidate = f"{prefix}…{tail}" if prefix else f"…{tail}"
            if val not in candidate:
                return candidate

    # Highly defensive fallback: redact any lingering occurrences explicitly.
    sanitized = candidate
    if val:
        replacement = "•" * len(val)
        while val in sanitized:
            sanitized = sanitized.replace(val, replacement)
    return sanitized


# Fields whose values are typically sensitive when PII logging is off.
_SENSITIVE_FIELDS: Tuple[str, ...] = (
    "headers",
    "authorization",
    "cookie",
    "set-cookie",
    "body",
    "request",
    "query",
    "email",
    "user",
)


def _scrub_fields(
    fields: Mapping[str, Any], include_pii: bool, mask_prefix_len: int
) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in fields.items():
        k_l = k.lower()

        # Always replace full key with masked prefix (never log full key).
        if k_l in ("key", "idempotency_key", "x-idempotency-key"):
            out["key_prefix"] = _mask_key(str(v), mask_prefix_len)
            continue

        # Drop obviously sensitive structures unless explicitly enabled.
        if not include_pii and k_l in _SENSITIVE_FIELDS:
            continue

        out[k] = v
    return out


def _pii_enabled() -> bool:
    # "1", "true", "yes", "on" → enabled
    raw = os.getenv("IDEMP_LOG_INCLUDE_PII", "0").strip().lower()
    return raw in {"1", "true", "yes", "on"}


# ---- public API ---------------------------------------------------------------


def log_idempotency_event(event: str, /, **fields: Any) -> None:
    """Emit a structured idempotency event with safe defaults."""
    # Read effective settings (for mask length).
    effective = settings_module.settings.idempotency
    mask_prefix_len: int = int(getattr(effective, "mask_prefix_len", 8))

    include_pii = _pii_enabled()
    payload = _scrub_fields(fields, include_pii, mask_prefix_len)
    # Attach envelope fields that make privacy posture explicit downstream.
    payload["event"] = event
    payload["privacy_mode"] = "pii_enabled" if include_pii else "pii_disabled"
    payload["mask_prefix_len"] = mask_prefix_len

    # Log compact JSON for ingestion.
    _LOG.info(json.dumps(payload, separators=(",", ":")))

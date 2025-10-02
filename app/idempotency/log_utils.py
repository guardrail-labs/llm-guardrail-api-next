"""Structured logging helpers for idempotency events.

Guarantees:
- Never log the full idempotency key; only a masked prefix.
- Optional PII logging toggle via env IDEMP_LOG_INCLUDE_PII (default: 0 / disabled).
- Preserve core operational fields used by dashboards & runbooks.

Fields we keep (non-PII):
- tenant, role, state, replay_count, fp_prefix, wait_ms (when provided)
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, Mapping, Optional, Tuple

from app import settings as settings_module

_LOG = logging.getLogger("app.idempotency")


# ---- helpers -----------------------------------------------------------------


def _mask_key(val: Optional[str], prefix_len: int) -> Optional[str]:
    if not val:
        return val
    prefix = val[: max(0, int(prefix_len))]
    ellipsis = "…" if len(val) > len(prefix) else ""
    return f"{prefix}{ellipsis}"


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

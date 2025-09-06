from __future__ import annotations

import json
import os
import random
import re
import time
import uuid
from typing import Any, Dict, Tuple

from app.services.audit_forwarder import emit_audit_event as _forward_emit
from app.services.policy import current_rules_version

# ------------------------- env helpers -------------------------

def _getenv(name: str, default: str = "") -> str:
    try:
        return os.getenv(name, default)
    except Exception:
        return default


def _truthy(val: object) -> bool:
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


def _float_in_range(val: str, lo: float, hi: float, default: float) -> float:
    try:
        f = float(val)
        if f < lo or f > hi:
            return default
        return f
    except Exception:
        return default


# ------------------------- config -------------------------

_APP_NAME = _getenv("APP_NAME", "llm-guardrail-api")
_ENV = _getenv("ENV", _getenv("APP_ENV", ""))

_SAMPLE_RATE = _float_in_range(_getenv("AUDIT_SAMPLE_RATE", "1.0"), 0.0, 1.0, 1.0)
_SCRUB_ENABLED = _truthy(_getenv("AUDIT_SCRUB_ENABLED", "1"))
_MAX_EVENT_BYTES = 0
try:
    _MAX_EVENT_BYTES = max(0, int(_getenv("AUDIT_MAX_EVENT_BYTES", "0")))
except Exception:
    _MAX_EVENT_BYTES = 0


# ------------------------- scrubbers -------------------------

# Basic, conservative patterns; mirror redaction ideas without being brittle.
_RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_RE_PHONE = re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b")
_RE_OPENAI = re.compile(r"\bsk-[A-Za-z0-9]{24,}\b")
_RE_AWS = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_RE_PRIVKEY_ENVELOPE = re.compile(
    r"-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----", re.S
)
_RE_PRIVKEY_MARKER = re.compile(
    r"(?:-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----)"
)

_MASKS: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (_RE_PRIVKEY_ENVELOPE, "[REDACTED:PRIVATE_KEY]"),
    (_RE_PRIVKEY_MARKER, "[REDACTED:PRIVATE_KEY]"),
    (_RE_OPENAI, "[REDACTED:OPENAI_KEY]"),
    (_RE_AWS, "[REDACTED:AWS_ACCESS_KEY_ID]"),
    (_RE_EMAIL, "[REDACTED:EMAIL]"),
    (_RE_PHONE, "[REDACTED:PHONE]"),
)


def _scrub_string(s: str) -> str:
    out = s
    for rx, repl in _MASKS:
        if rx.search(out):
            out = rx.sub(repl, out)
    return out


def _scrub_value(val: Any) -> Any:
    # Recursively scrub strings inside typical JSON structures
    if isinstance(val, str):
        return _scrub_string(val)
    if isinstance(val, dict):
        return {k: _scrub_value(v) for k, v in val.items()}
    if isinstance(val, list):
        return [_scrub_value(v) for v in val]
    if isinstance(val, tuple):
        return tuple(_scrub_value(v) for v in val)
    return val


# ------------------------- size limiting -------------------------

_HEAVY_KEYS_ORDER: Tuple[str, ...] = (
    # Drop these first if we need to shrink the event
    "debug_sources",
    "matches",
    "decisions",
    "rule_hits_detailed",
    "meta",
)


def _event_size_bytes(ev: Dict[str, Any]) -> int:
    try:
        return len(json.dumps(ev, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    except Exception:
        # Fall back to a rough estimate
        return len(str(ev).encode("utf-8", errors="ignore"))


def _clip_text(s: str, max_len: int) -> Tuple[str, int]:
    if len(s) <= max_len:
        return s, 0
    return s[:max_len], len(s) - max_len


def _shrink_event(ev: Dict[str, Any], max_bytes: int) -> Dict[str, Any]:
    """
    Best-effort size cap without breaking structure:
      1) Try removing heavy optional fields
      2) Clip very long text fields
      3) If still large, attach overflow hint
    """
    if max_bytes <= 0:
        return ev

    out = dict(ev)  # shallow copy ok
    if _event_size_bytes(out) <= max_bytes:
        return out

    # 1) drop heavy keys if present
    for k in _HEAVY_KEYS_ORDER:
        if k in out:
            out.pop(k, None)
            if _event_size_bytes(out) <= max_bytes:
                out["audit_truncated"] = True
                return out
    # 2) clip common large strings
    over = _event_size_bytes(out) - max_bytes
    if over > 0:
        # Heuristic budget: keep ~2k each for text fields if present
        budget_each = 2000
        clipped_total = 0
        for key in ("text", "transformed_text"):
            if isinstance(out.get(key), str):
                new_s, clipped = _clip_text(out[key], budget_each)
                if clipped > 0:
                    out[key] = new_s + "…"
                    clipped_total += clipped
        if clipped_total:
            out["audit_truncated"] = True

    # 3) If still big, mark overflow; downstream can decide to drop
    if _event_size_bytes(out) > max_bytes:
        out["audit_overflow_bytes"] = _event_size_bytes(out) - max_bytes
        out["audit_truncated"] = True

    return out


# ------------------------- facade -------------------------

def emit_audit_event(event: Dict[str, Any]) -> None:
    """
    Facade for audit forwarding that normalizes/annotates payloads and
    applies hygiene controls (sampling, scrubbing, size caps).
    """
    if not isinstance(event, dict):
        return

    # --- sampling (fast path) ---
    if _SAMPLE_RATE < 1.0:
        if random.random() > _SAMPLE_RATE:
            return

    # --- normalize required bits ---
    event = dict(event)  # avoid mutating caller object

    if not event.get("policy_version"):
        try:
            event["policy_version"] = current_rules_version()
        except Exception:
            pass

    if not event.get("request_id"):
        event["request_id"] = str(uuid.uuid4())

    if event.get("ts") in (None, "", 0):
        try:
            event["ts"] = int(time.time())
        except Exception:
            pass

    event.setdefault("service", _APP_NAME)
    if _ENV:
        event.setdefault("env", _ENV)

    # --- scrub & cap ---
    if _SCRUB_ENABLED:
        try:
            event = _scrub_value(event)
        except Exception:
            # best-effort only
            pass

    if _MAX_EVENT_BYTES > 0:
        try:
            event = _shrink_event(event, _MAX_EVENT_BYTES)
        except Exception:
            pass

    _forward_emit(event)

# Env knobs (optional)
#
# AUDIT_SAMPLE_RATE=0.25 → keep ~25% of audit events
#
# AUDIT_SCRUB_ENABLED=1 → (default) mask secrets/PII in audit payload
#
# AUDIT_MAX_EVENT_BYTES=32768 → cap each event to ~32 KB, trimming heavy fields first

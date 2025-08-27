from __future__ import annotations

import json
import logging
import os
from typing import Iterable

_AUDIT_LOGGER_NAME = "guardrail_audit"
_logger = logging.getLogger(_AUDIT_LOGGER_NAME)
_logger.setLevel(logging.INFO)

# Simple counter for Prometheus-style metrics.
# Incremented each time an audit event is actually emitted.
_audit_events_total: int = 0


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "on"}


def emit_decision_event(
    *,
    request_id: str,
    decision: str,
    rule_hits: Iterable[str],
    reason: str,
    policy_version: str,
    prompt_text: str,
) -> None:
    """Emit a single-line JSON audit record. Honors:
    - AUDIT_ENABLED (default: false)
    - AUDIT_SAMPLE_RATE (0.0..1.0, default: 1.0)
    - AUDIT_MAX_TEXT_CHARS (default: 128) -> truncates snippet
    - SERVICE_NAME (default: llm-guardrail-api-next)
    - ENV (default: dev)
    """
    if not _truthy(os.getenv("AUDIT_ENABLED", "false")):
        return

    try:
        sample_rate = float(os.getenv("AUDIT_SAMPLE_RATE", "1.0"))
    except Exception:
        sample_rate = 1.0

    # Cheap sampling without importing random if always-on
    if sample_rate < 1.0:
        import random

        if random.random() > sample_rate:
            return

    try:
        max_chars = int(os.getenv("AUDIT_MAX_TEXT_CHARS", "128"))
    except Exception:
        max_chars = 128

    snippet_full = prompt_text or ""
    snippet = snippet_full[:max_chars]
    snippet_truncated = len(snippet_full) > max_chars

    payload = {
        "event": "guardrail_decision",
        "request_id": request_id,
        "decision": str(decision),
        "rule_hits": list(rule_hits),
        "reason": str(reason),
        "policy_version": str(policy_version),
        "prompt_len": len(snippet_full),
        "snippet_len": len(snippet),
        "snippet": snippet,
        "snippet_truncated": snippet_truncated,
        "service": os.getenv("SERVICE_NAME", "llm-guardrail-api-next"),
        "env": os.getenv("ENV", "dev"),
    }

    _logger.info(json.dumps(payload))
    global _audit_events_total
    _audit_events_total += 1


def get_audit_events_total() -> int:
    """Return the number of audit events emitted so far."""
    return _audit_events_total

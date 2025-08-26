"""Structured audit logging with sampling and optional file rotation."""
from __future__ import annotations

import json
import logging
import os
import random
from logging.handlers import RotatingFileHandler
from typing import Any, Dict

from app.config import Settings
from app.telemetry.metrics import inc_audit_event

_LOGGER_NAME = "guardrail_audit"
_configured = False


def _ensure_logger() -> logging.Logger:
    global _configured
    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(logging.INFO)
    logger.propagate = False  # don't duplicate to root

    if _configured:
        return logger

    s = Settings()
    formatter = logging.Formatter("%(message)s")

    if s.AUDIT_LOG_FILE:
        handler = RotatingFileHandler(
            filename=s.AUDIT_LOG_FILE,
            maxBytes=int(s.AUDIT_LOG_MAX_BYTES),
            backupCount=int(s.AUDIT_LOG_BACKUPS),
            encoding="utf-8",
        )
    else:
        handler = logging.StreamHandler()

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    _configured = True
    return logger


def _should_sample(rate: float) -> bool:
    if rate <= 0.0:
        return False
    if rate >= 1.0:
        return True
    return random.random() < rate


def emit_decision_event(
    *,
    request_id: str,
    decision: str,
    rule_hits: list[str],
    reason: str,
    transformed_text: str,
    policy_version: str,
    prompt_len: int,
) -> None:
    """Emit a single JSON line audit event if enabled and sampled."""
    s = Settings()

    if not s.AUDIT_ENABLED:
        return
    if not _should_sample(float(s.AUDIT_SAMPLE_RATE)):
        return

    max_chars = int(s.AUDIT_MAX_TEXT_CHARS)
    snippet = transformed_text[:max_chars]
    redacted = snippet != transformed_text and len(transformed_text) > max_chars

    payload: Dict[str, Any] = {
        "event": "guardrail_decision",
        "request_id": request_id,
        "decision": decision,
        "rule_hits": sorted(rule_hits),
        "reason": reason,
        "policy_version": policy_version,
        "prompt_len": prompt_len,
        "snippet_len": len(snippet),
        "snippet": snippet,
        "snippet_truncated": redacted,
        "service": Settings().APP_NAME,
        "env": os.environ.get("APP_ENV", "dev"),
    }

    try:
        _ensure_logger().info(json.dumps(payload, ensure_ascii=False))
        inc_audit_event()
    except Exception:
        # Never let audit logging break the request path
        pass


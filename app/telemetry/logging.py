from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any, Dict

from app.telemetry.tracing import get_request_id, get_trace_id

# -----------------------------------------------------------------------------
# Structured JSON logging for audit lines (and a helper to get a base logger).
# -----------------------------------------------------------------------------

class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:  # noqa: D401
        """Render LogRecord as a compact JSON line."""
        payload: Dict[str, Any] = {
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Attach contextual IDs if present
        rid = get_request_id()
        if rid:
            payload["request_id"] = rid
        tid = get_trace_id()
        if tid:
            payload["trace_id"] = tid

        # Include extras when record contains dict-like arguments
        if hasattr(record, "extra") and isinstance(record.extra, dict):
            payload.update(record.extra)  # type: ignore[arg-type]

        # Fallback: include record.__dict__ keys that look like structured extras
        for key in ("event", "audit", "tenant_id", "bot_id", "action"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)

        return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


def _ensure_handler(logger: logging.Logger) -> None:
    if logger.handlers:
        return
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(_JsonFormatter())
    logger.addHandler(handler)
    logger.propagate = False  # keep audit lines single-written


def get_audit_logger(name: str = "audit") -> logging.Logger:
    """
    Returns a JSON-structured logger for audit lines.
    Level is controlled by AUDIT_LOG_LEVEL (default INFO).
    """
    logger = logging.getLogger(name)
    level_name = os.getenv("AUDIT_LOG_LEVEL", "INFO").upper()
    try:
        logger.setLevel(getattr(logging, level_name))
    except Exception:
        logger.setLevel(logging.INFO)
    _ensure_handler(logger)
    return logger


def get_app_logger(name: str = "app") -> logging.Logger:
    """
    Simple application logger (non-JSON). Useful for internal diagnostics.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(stream=sys.stdout)
        formatter = logging.Formatter(
            fmt="%(asctime)s %(levelname)s %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.propagate = False
    logger.setLevel(logging.INFO)
    return logger

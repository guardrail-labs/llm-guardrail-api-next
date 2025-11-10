# app/telemetry/logging.py
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, MutableMapping, Tuple

from app.telemetry.tracing import get_request_id, get_trace_id


# ------------------------------- JSON utilities -------------------------------


def _iso8601(dt: datetime) -> str:
    # Always UTC, explicit trailing 'Z'
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


_JSON_SAFE_PRIMITIVES = (str, int, float, bool, type(None))


def _json_sanitize(value: Any) -> Any:
    """
    Best-effort JSON sanitizer for log payloads:
    - Pass through JSON-safe primitives
    - Convert bytes to utf-8 (errors replaced)
    - Convert datetimes to ISO8601
    - Fallback to str(value)
    """
    if isinstance(value, _JSON_SAFE_PRIMITIVES):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, datetime):
        return _iso8601(value)
    if isinstance(value, Mapping):
        return {str(k): _json_sanitize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_sanitize(v) for v in value]
    return str(value)


# ------------------------------ JSON formatter --------------------------------


class JsonFormatter(logging.Formatter):
    """
    Minimal, fast JSON formatter with stable keys. Ensures all fields are
    JSON-serializable and line-oriented.
    """

    # Standard LogRecord attributes to exclude from "extra"
    _std_keys: Tuple[str, ...] = (
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "exc_info",
        "exc_text",
        "stack_info",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
    )

    def format(self, record: logging.LogRecord) -> str:
        # message resolving (handles %-style on .msg/.args)
        message = record.getMessage()

        # collect "extra" fields that are not standard record attributes
        extra: Dict[str, Any] = {}
        for k, v in record.__dict__.items():
            if k not in self._std_keys and not k.startswith("_"):
                extra[k] = v

        # attach request/trace IDs if not already present
        rid = extra.get("request_id") or get_request_id()
        tid = extra.get("trace_id") or get_trace_id()

        payload: Dict[str, Any] = {
            "ts": _iso8601(
                datetime.utcfromtimestamp(record.created).replace(tzinfo=timezone.utc)
            ),
            "level": record.levelname,
            "logger": record.name,
            "message": message,
        }

        if rid:
            payload["request_id"] = rid
        if tid:
            payload["trace_id"] = tid

        if extra:
            payload.update(_json_sanitize(extra))

        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)

        return json.dumps(payload, ensure_ascii=False)


# ------------------------------ Logger helpers --------------------------------


_configured = False


def configure_root_logging(level: int | str = "INFO") -> None:
    """
    Idempotent root logger setup for JSON logs to stdout. Safe for tests.
    """
    global _configured
    if _configured:
        return

    root = logging.getLogger()

    resolved_level = (
        level if isinstance(level, int) else getattr(logging, str(level).upper(), logging.INFO)
    )
    root.setLevel(resolved_level)

    # Remove pre-existing handlers to avoid duplicate lines in tests
    for h in list(root.handlers):
        root.removeHandler(h)

    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)

    _configured = True


class ContextAdapter(logging.LoggerAdapter[logging.Logger]):
    """
    Bind static context (e.g., tenant_id, component) to a logger, ensuring those
    keys appear on every log line via the 'extra' mechanism.
    """

    def __init__(self, logger: logging.Logger, extra: Mapping[str, Any] | None = None):
        # Store a plain dict to satisfy LoggerAdapter expectations
        super().__init__(logger, dict(extra or {}))

    def process(
        self, msg: Any, kwargs: MutableMapping[str, Any]
    ) -> Tuple[Any, MutableMapping[str, Any]]:
        # Merge adapter's context with per-call extra (if any)
        merged_extra: Dict[str, Any] = {}
        call_extra = kwargs.get("extra")
        if isinstance(call_extra, Mapping):
            merged_extra.update(dict(call_extra))
        for k, v in self.extra.items():
            merged_extra.setdefault(k, v)
        kwargs["extra"] = merged_extra
        return msg, kwargs


def bind(logger: logging.Logger | None = None, **context: Any) -> ContextAdapter:
    """
    Return a LoggerAdapter with bound context.

        log = bind(logging.getLogger(__name__), tenant_id="acme", component="proxy")
        log.info("started")

    If logger is None, the root logger is used.
    """
    base = logger or logging.getLogger()
    return ContextAdapter(base, context)

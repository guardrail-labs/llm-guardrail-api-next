from __future__ import annotations

import json
import os
import random
import socket
import ssl
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse
from http.client import HTTPConnection, HTTPSConnection  # <- explicit imports

from app.telemetry.logging import get_audit_logger
from app.telemetry.tracing import get_request_id, get_trace_id

# Public symbol expected by routes/tests
__all__ = ["emit_audit_event"]

_audit_log = get_audit_logger("audit")


# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

def _truthy(val: object) -> bool:
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


def _get_cfg() -> Dict[str, Any]:
    return {
        "enabled": _truthy(os.getenv("AUDIT_FORWARD_ENABLED", "false")),
        "url": os.getenv("AUDIT_FORWARD_URL", ""),
        "api_key": os.getenv("AUDIT_FORWARD_API_KEY", ""),
        "sample_rate": float(os.getenv("AUDIT_SAMPLE_RATE", "1.0") or "1.0"),
        "timeout": float(os.getenv("AUDIT_FORWARD_TIMEOUT_SECS", "5") or "5"),
        "retries": int(os.getenv("AUDIT_FORWARD_RETRIES", "1") or "1"),
        "backoff": float(os.getenv("AUDIT_FORWARD_BACKOFF_SECS", "0.25") or "0.25"),
    }


# -----------------------------------------------------------------------------
# HTTP posting (kept simple; tests monkeypatch _post)
# -----------------------------------------------------------------------------

def _post(url: str, api_key: str, payload: Dict[str, Any]) -> Tuple[int, str]:
    """
    Minimal HTTP/HTTPS JSON POST with API key header.
    Returns (status_code, response_text). Raises on connection errors.
    Tests patch this function.
    """
    parsed = urlparse(url)
    use_tls = parsed.scheme == "https"
    host = parsed.hostname or ""
    port = parsed.port or (443 if use_tls else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    # Annotate to supertype so both HTTPConnection and HTTPSConnection assign cleanly
    conn: HTTPConnection
    if use_tls:
        context = ssl.create_default_context()
        conn = HTTPSConnection(host, port, timeout=5, context=context)
    else:
        conn = HTTPConnection(host, port, timeout=5)

    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
        "User-Agent": "llm-guardrail-audit-forwarder/1",
    }
    conn.request("POST", path, body=body, headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    try:
        text = data.decode("utf-8")
    except Exception:
        text = ""
    status = getattr(resp, "status", 0) or 0
    conn.close()
    return status, text


# -----------------------------------------------------------------------------
# Core API
# -----------------------------------------------------------------------------

def _should_sample(rate: float) -> bool:
    if rate >= 1.0:
        return True
    if rate <= 0.0:
        return False
    return random.random() < rate


def _enrich(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Attach request_id and trace_id if available; copy tenant/bot if provided in event.
    Do not mutate caller's dict.
    """
    out = dict(event)
    rid = out.get("request_id") or get_request_id()
    tid = out.get("trace_id") or get_trace_id()
    if rid:
        out["request_id"] = rid
    if tid:
        out["trace_id"] = tid
    return out


def emit_audit_event(event: Dict[str, Any]) -> None:
    """
    Public entrypoint. Always logs a structured audit line.
    Optionally forwards to external sink when enabled.
    """
    cfg = _get_cfg()

    # Sampling: still *log locally* even if not forwarded
    sampled = _should_sample(cfg["sample_rate"])

    enriched = _enrich(event)
    # Ensure minimal shape for local audit stream
    minimal = {
        "event": "audit",
        "action": enriched.get("action", "unknown"),
        "tenant_id": enriched.get("tenant_id"),
        "bot_id": enriched.get("bot_id"),
        "request_id": enriched.get("request_id"),
        "trace_id": enriched.get("trace_id"),
    }
    # Merge everything into the audit log line
    _audit_log.info("audit event", extra={"extra": {**minimal, **enriched}})

    # Forward if configured, sampled, and config sane
    if not (cfg["enabled"] and cfg["url"] and cfg["api_key"] and sampled):
        return

    # Transmit with small retry/backoff
    attempts = 1 + max(0, int(cfg["retries"]))
    backoff = max(0.0, float(cfg["backoff"]))
    last_exc: Optional[BaseException] = None
    for i in range(attempts):
        try:
            status, _ = _post(cfg["url"], cfg["api_key"], enriched)
            # Accept any 2xx as success
            if 200 <= status < 300:
                return
        except (socket.timeout, ConnectionError, OSError, ssl.SSLError) as exc:  # pragma: no cover - network
            last_exc = exc
        # backoff before next try, except after last attempt
        if i < attempts - 1 and backoff:
            time.sleep(backoff)  # pragma: no cover - timing

    # If we exhausted retries, we swallow the error (audit logging is best-effort).
    if last_exc:
        _audit_log.debug(
            "audit forward failed",
            extra={"extra": {"error": str(last_exc)}},
        )

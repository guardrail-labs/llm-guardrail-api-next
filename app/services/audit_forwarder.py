from __future__ import annotations

import http.client
import json
import os
import time
from typing import Any, Dict, Optional, Tuple, cast

# ---- config helpers ---------------------------------------------------------

def _truthy(val: object) -> bool:
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


def _env(name: str, default: str = "") -> str:
    v = os.getenv(name)
    return v if v is not None else default


# ---- trace correlation (safe/optional) --------------------------------------

def _current_trace_ids() -> Tuple[Optional[str], Optional[str]]:
    """
    Return (trace_id_hex, span_id_hex) if OpenTelemetry is active and a current span exists.
    Otherwise (None, None). Never raises.
    """
    try:
        # Import lazily; OTel is optional
        from opentelemetry.trace import get_current_span
    except Exception:
        return None, None

    try:
        span = get_current_span()
        # In OTel, a non-recording default span may exist; guard against zero IDs.
        ctx = span.get_span_context()
        if ctx is None:
            return None, None

        trace_id = getattr(ctx, "trace_id", 0)
        span_id = getattr(ctx, "span_id", 0)

        # Zero means "invalid" in OTel
        if not trace_id or not span_id:
            return None, None

        # Convert to hex (zero-padded per spec)
        trace_hex = f"{trace_id:032x}"
        span_hex = f"{span_id:016x}"
        return trace_hex, span_hex
    except Exception:
        return None, None


# ---- HTTP transport (patch point for tests) ---------------------------------

def _post(url: str, api_key: str, payload: Dict[str, Any]) -> Tuple[int, str]:
    """
    Minimal HTTP POST using stdlib http.client so tests can monkeypatch `_post`
    without extra deps. Returns (status_code, response_body).
    """
    # Parse URL (http only; CI tests patch this anyway)
    if not url.startswith("http://") and not url.startswith("https://"):
        raise ValueError("AUDIT_FORWARD_URL must be http(s)")

    is_https = url.startswith("https://")
    prefix = "https://" if is_https else "http://"
    rest = url[len(prefix):]
    host, path = (rest.split("/", 1) + [""])[:2]
    path = "/" + path

    conn_cls = http.client.HTTPSConnection if is_https else http.client.HTTPConnection
    conn = cast(http.client.HTTPConnection, conn_cls(host, timeout=5))

    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "llm-guardrail-audit-forwarder/1.0",
        "Authorization": f"Bearer {api_key}",
    }
    conn.request("POST", path, body=body, headers=headers)
    resp = conn.getresponse()
    data = resp.read().decode("utf-8", errors="replace")
    try:
        conn.close()
    finally:
        pass
    return getattr(resp, "status", 200), data


# ---- public API --------------------------------------------------------------

def emit_audit_event(event: Dict[str, Any]) -> None:
    """
    Fire-and-forget audit event forwarder. When the forwarder is disabled,
    this function is a no-op. When enabled, it forwards to AUDIT_FORWARD_URL
    with AUDIT_FORWARD_API_KEY. It also enriches the payload with trace ids
    (if OpenTelemetry tracing is active) under keys `trace_id` and `span_id`.

    Contract: this function **must not** raise; any internal error is swallowed.
    """
    try:
        if not _truthy(_env("AUDIT_FORWARD_ENABLED", "false")):
            return

        url = _env("AUDIT_FORWARD_URL")
        api_key = _env("AUDIT_FORWARD_API_KEY")
        if not url or not api_key:
            # Misconfigured; quietly skip
            return

        # Non-destructive trace enrichment
        trace_id, span_id = _current_trace_ids()
        if trace_id and "trace_id" not in event:
            event["trace_id"] = trace_id
        if span_id and "span_id" not in event:
            event["span_id"] = span_id

        # Basic envelope metadata if caller didn't include it
        event.setdefault("timestamp", int(time.time()))
        event.setdefault("kind", "guardrail")

        _post(url, api_key, event)
    except Exception:
        # Never let audit forwarding affect the request path
        return


from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import logging
import socket
import ssl
import time
from typing import Any, Dict, Optional, Tuple, Union
from urllib.parse import urlparse

from app.services.metrics import audit_forwarder_requests_total

log = logging.getLogger(__name__)


# ----------------------------- helpers ---------------------------------------


def _truthy(val: object) -> bool:
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


def _getenv(name: str, default: str = "") -> str:
    # Local import to avoid polluting module namespace for typing/mypy.
    import os

    return os.getenv(name, default)


# ------------------------ HTTP connection creator ----------------------------


def _http_connection_for(
    url: str,
) -> Union[http.client.HTTPConnection, http.client.HTTPSConnection]:
    """
    Return the correct HTTP(S) connection object for a given URL.
    """
    parsed = urlparse(url)
    scheme = (parsed.scheme or "http").lower()
    host = parsed.hostname or "localhost"
    port: Optional[int] = parsed.port

    if scheme == "https":
        return http.client.HTTPSConnection(host, port, timeout=5)
    # Default to HTTP whenever scheme isn't https
    return http.client.HTTPConnection(host, port, timeout=5)


# ----------------------------- Core posting ----------------------------------


def _post(url: str, api_key: str, payload: Dict[str, Any]) -> Tuple[int, str]:
    """
    Low-level POST used by emit_audit_event. Tests monkeypatch this symbol.
    Returns (status_code, response_text).
    """
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "llm-guardrail-audit-forwarder/1.0",
        # The receiving service expects an API key header; keep name stable.
        "X-API-Key": api_key,
    }

    # Optional request signing: HMAC-SHA256 over "ts + '.' + body"
    secret = _getenv("AUDIT_FORWARD_SIGNING_SECRET", "")
    if secret:
        ts = str(int(time.time()))
        msg = ts.encode("utf-8") + b"." + body
        digest = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()
        headers["X-Signature-Ts"] = ts
        headers["X-Signature"] = f"sha256={digest}"

    conn = _http_connection_for(url)
    try:
        conn.request("POST", path, body=body, headers=headers)
        resp = conn.getresponse()
        status = resp.status
        text = (resp.read() or b"").decode("utf-8", errors="replace")
        return status, text
    finally:
        try:
            conn.close()
        except Exception:
            pass


# ----------------------------- Public API ------------------------------------


def emit_audit_event(event: Dict[str, Any]) -> None:
    """
    Fire-and-forget forwarder. Honors env flag AUDIT_FORWARD_ENABLED.

    Env:
      - AUDIT_FORWARD_ENABLED: if falsey, no-op
      - AUDIT_FORWARD_URL: destination endpoint
      - AUDIT_FORWARD_API_KEY: bearer secret to include in header
      - AUDIT_FORWARD_RETRIES: optional, default 3
      - AUDIT_FORWARD_BACKOFF_MS: optional, default 100 (linear backoff)
      - AUDIT_FORWARD_SIGNING_SECRET: if set, add HMAC over 'ts.body' headers
    """
    if not _truthy(_getenv("AUDIT_FORWARD_ENABLED", "false")):
        return

    url = _getenv("AUDIT_FORWARD_URL")
    api_key = _getenv("AUDIT_FORWARD_API_KEY")
    if not url or not api_key:
        log.warning("Audit forwarder enabled but URL or API key is missing.")
        return

    # Light validation of payload to avoid surprises downstream.
    if not isinstance(event, dict):
        log.debug("Audit event ignored; expected dict, got %r.", type(event))
        return

    retries_raw = _getenv("AUDIT_FORWARD_RETRIES", "3")
    backoff_ms_raw = _getenv("AUDIT_FORWARD_BACKOFF_MS", "100")
    try:
        retries = max(1, int(retries_raw))
    except Exception:
        retries = 3
    try:
        backoff_ms = max(0, int(backoff_ms_raw))
    except Exception:
        backoff_ms = 100

    last_exc: Optional[BaseException] = None
    for attempt in range(retries):
        try:
            status, _text = _post(url, api_key, event)
            # Consider 2xx success; otherwise proceed to retry loop.
            if 200 <= status < 300:
                audit_forwarder_requests_total.labels("success").inc()
                return
        except (  # pragma: no cover - network
            socket.timeout,
            ConnectionError,
            OSError,
            ssl.SSLError,
        ) as exc:
            last_exc = exc
        # backoff before next try, except after last attempt
        if attempt < retries - 1:
            _sleep_ms(backoff_ms * (attempt + 1))

    # Failed after retries (either non-2xx or exception)
    audit_forwarder_requests_total.labels("failure").inc()
    if last_exc is not None:  # pragma: no cover - network
        log.warning(
            "Audit forwarder failed after %d attempts: %s", retries, last_exc
        )
    else:
        log.warning(
            "Audit forwarder non-2xx response after %d attempts.", retries
        )


def _sleep_ms(ms: int) -> None:
    # Isolated to allow deterministic tests if ever needed.
    import time

    time.sleep(ms / 1000.0)

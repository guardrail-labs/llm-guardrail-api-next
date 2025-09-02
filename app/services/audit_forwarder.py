from __future__ import annotations

import http.client
import json
import logging
import socket
import ssl
import time
from typing import Any, Dict, Tuple, Union
from urllib.parse import urlparse

log = logging.getLogger(__name__)

# Public toggle and config via env handled by caller/tests. This file focuses on
# a clean, typed emitter plus a small retry/backoff wrapper.


def _http_connection_for(url: str) -> Union[http.client.HTTPConnection, http.client.HTTPSConnection]:
    """
    Return the correct HTTP(S) connection object for a given URL.
    """
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port: int

    if parsed.scheme == "https":
        port = parsed.port or 443
        return http.client.HTTPSConnection(host, port, timeout=5)
    if parsed.scheme == "http":
        port = parsed.port or 80
        return http.client.HTTPConnection(host, port, timeout=5)

    raise ValueError(f"Unsupported URL scheme: {parsed.scheme!r}")


def _post(url: str, api_key: str, payload: Dict[str, Any]) -> Tuple[int, str]:
    """
    Raw POST used by tests (monkeypatched) and by emit_audit_event().
    Returns (status_code, response_text).
    """
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    conn = _http_connection_for(url)

    try:
        body = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        }
        conn.request("POST", path, body=body, headers=headers)
        resp = conn.getresponse()
        text = resp.read().decode("utf-8", "replace")
        status = int(resp.status)
        return (status, text)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def emit_audit_event(event: Dict[str, Any]) -> None:
    """
    Fire-and-forget best-effort forwarder. Reads config from env at call time.

    Expected env (set by process/tests):
      - AUDIT_FORWARD_ENABLED: truthy to enable
      - AUDIT_FORWARD_URL: destination URL
      - AUDIT_FORWARD_API_KEY: bearer value
      - AUDIT_FORWARD_MAX_RETRIES (optional): default 2
      - AUDIT_FORWARD_BACKOFF_SECONDS (optional): default 0.15
    """
    import os

    enabled = str(os.getenv("AUDIT_FORWARD_ENABLED", "false")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if not enabled:
        return

    url = os.getenv("AUDIT_FORWARD_URL", "")
    api_key = os.getenv("AUDIT_FORWARD_API_KEY", "")
    if not url or not api_key:
        log.warning("Audit forwarder enabled but missing URL or API key; skipping emit.")
        return

    # Optional tuning
    try:
        max_retries = int(os.getenv("AUDIT_FORWARD_MAX_RETRIES", "2"))
    except ValueError:
        max_retries = 2
    try:
        backoff = float(os.getenv("AUDIT_FORWARD_BACKOFF_SECONDS", "0.15"))
    except ValueError:
        backoff = 0.15

    last_exc: Exception | None = None

    for attempt in range(max_retries + 1):
        try:
            status, _ = _post(url, api_key, event)
            # 2xx success
            if 200 <= status < 300:
                return
        except (socket.timeout, ConnectionError, OSError, ssl.SSLError) as exc:
            last_exc = exc

        # Backoff before next try (except after final attempt)
        if attempt < max_retries:
            time.sleep(backoff)

    # Log once on failure after retries
    if last_exc is not None:
        log.warning("Audit forward failed after retries: %s", last_exc)
    else:
        log.warning("Audit forward failed; non-2xx response")

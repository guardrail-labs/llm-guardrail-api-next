from __future__ import annotations

import json
import os
from typing import Any, Dict, Tuple, cast
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen  # stdlib only


def forward_enabled() -> bool:
    return os.getenv("AUDIT_FORWARD_ENABLED", "false").lower() == "true"


def _endpoint() -> Tuple[str, str]:
    url = os.getenv("AUDIT_FORWARD_URL", "").strip()
    key = os.getenv("AUDIT_FORWARD_API_KEY", "").strip()
    return url, key


def _post(url: str, api_key: str, payload: Dict[str, Any]) -> Tuple[int, str]:
    """
    Raw POST helper (sync). Swallows errors at callsites.
    Returns (status_code, body_text) on success.
    """
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    req = Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if api_key:
        req.add_header("X-API-Key", api_key)
    with urlopen(req, timeout=5) as resp:  # nosec - admin-controlled URL
        code = cast(int, resp.status)
        body = resp.read().decode("utf-8", "ignore")
        return code, body


def emit_event(event: Dict[str, Any]) -> None:
    """
    Fire-and-forget emitter. No exceptions propagate.
    """
    if not forward_enabled():
        return
    url, key = _endpoint()
    if not url:
        return
    try:
        _post(url, key, event)
    except (URLError, HTTPError, Exception):
        # Never break request flow due to forwarding issues
        return

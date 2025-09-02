from __future__ import annotations

import json
import os
import http.client
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

def _truthy(val: object) -> bool:
    return str(val).strip().lower() in {"1", "true", "yes", "on"}

def _get_forward_cfg() -> Tuple[bool, Optional[str], Optional[str]]:
    enabled = _truthy(os.getenv("AUDIT_FORWARD_ENABLED", "false"))
    url = os.getenv("AUDIT_FORWARD_URL")
    api_key = os.getenv("AUDIT_FORWARD_API_KEY")
    if not enabled or not url or not api_key:
        return False, None, None
    return True, url, api_key

def _post(url: str, api_key: str, payload: Dict[str, Any]) -> Tuple[int, str]:
    parsed = urlparse(url)
    host = parsed.netloc
    path = parsed.path or "/"
    scheme = parsed.scheme.lower()

    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
        "Content-Length": str(len(body)),
    }

    # Annotate as the base class; HTTPSConnection subclasses HTTPConnection.
    conn: http.client.HTTPConnection
    if scheme == "https":
        conn = http.client.HTTPSConnection(host, timeout=5)
    else:
        conn = http.client.HTTPConnection(host, timeout=5)

    try:
        conn.request("POST", path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8", errors="replace")
        return resp.status, data
    finally:
        try:
            conn.close()
        except Exception:
            pass

def emit_audit_event(event: Dict[str, Any]) -> None:
    enabled, url, key = _get_forward_cfg()
    if not enabled or not url or not key:
        return

    out: Dict[str, Any] = dict(event)
    meta = out.setdefault("meta", {})

    if isinstance(out.get("text"), str):
        meta.setdefault("text_size", len(out["text"]))
    if isinstance(out.get("prompt"), str):
        meta.setdefault("prompt_size", len(out["prompt"]))

    try:
        _post(url, key, out)
    except Exception:
        # Forwarding must never break the main flow.
        pass

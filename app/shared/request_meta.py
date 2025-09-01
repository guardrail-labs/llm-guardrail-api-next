from __future__ import annotations

from typing import Any, Dict

from fastapi import Request


def get_client_meta(request: Request) -> Dict[str, Any]:
    # Prefer first X-Forwarded-For hop if present (common behind proxies)
    xff = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    client_ip = xff or (getattr(request.client, "host", "") or "")
    ua = request.headers.get("User-Agent") or ""
    path = request.url.path
    method = request.method
    return {
        "client_ip": client_ip,
        "user_agent": ua,
        "path": path,
        "method": method,
    }

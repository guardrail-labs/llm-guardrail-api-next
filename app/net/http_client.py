from __future__ import annotations

import os
from typing import Optional

import httpx

_client: Optional[httpx.AsyncClient] = None


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default


def get_http_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        limits = httpx.Limits(
            max_connections=_int("HTTPX_MAX_CONNECTIONS", 200),
            max_keepalive_connections=_int("HTTPX_MAX_KEEPALIVE", 100),
            keepalive_expiry=_int("HTTPX_KEEPALIVE_S", 20),
        )
        _client = httpx.AsyncClient(
            timeout=_int("HTTPX_TIMEOUT_S", 30),
            limits=limits,
        )
    return _client

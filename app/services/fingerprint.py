from __future__ import annotations

import hashlib
import os

from fastapi import Request


def _extract_ip(req: Request) -> str:
    xfwd = req.headers.get("x-forwarded-for", "") or ""
    if xfwd:
        return xfwd.split(",")[0].strip()
    client = req.client
    return client.host if client else "0.0.0.0"


def get_fingerprint(req: Request) -> str:
    """
    Produces a stable, non-reversible fingerprint hash from request attributes.
    Uses: X-API-Key (if any), IP (or X-Forwarded-For), and User-Agent.
    """
    api_key = req.headers.get("x-api-key", "")
    ip = _extract_ip(req)
    ua = req.headers.get("user-agent", "")
    salt = os.getenv("FINGERPRINT_SALT", "guardrail")
    m = hashlib.sha256()
    m.update(salt.encode("utf-8"))
    m.update(b"|")
    m.update(api_key.encode("utf-8"))
    m.update(b"|")
    m.update(ip.encode("utf-8"))
    m.update(b"|")
    m.update(ua.encode("utf-8"))
    return m.hexdigest()

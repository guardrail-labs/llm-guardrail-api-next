from __future__ import annotations

import hashlib
import os
from typing import Iterable

from fastapi import Request

_PEPPER = os.getenv("ESCALATION_HASH_PEPPER", "guardrail-pepper")


def _extract_ip(req: Request) -> str:
    xfwd = req.headers.get("x-forwarded-for", "") or ""
    if xfwd:
        return xfwd.split(",")[0].strip()
    client = req.client
    return client.host if client else "0.0.0.0"


def _parts(req: Request) -> Iterable[str]:
    tenant = req.headers.get("X-Tenant") or req.headers.get("X-Tenant-ID") or "unknown"
    bot = req.headers.get("X-Bot") or req.headers.get("X-Bot-ID") or "unknown"
    ua = req.headers.get("User-Agent") or req.headers.get("user-agent") or "unknown"
    api_key = req.headers.get("X-API-Key") or req.headers.get("x-api-key") or "unknown"
    ip = _extract_ip(req) or "unknown"
    return tenant, bot, ua, api_key, ip, _PEPPER


def fingerprint(req: Request) -> str:
    """Generate a stable, non-PII fingerprint for escalation tracking."""

    base = "|".join(str(part) for part in _parts(req))
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


def get_fingerprint(req: Request) -> str:
    """Backward-compatible alias for callers still importing this helper."""

    return fingerprint(req)

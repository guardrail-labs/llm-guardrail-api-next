# app/middleware/cors.py
# Summary (PR-K fix):
# - Keep CORS behind CORS_ENABLED=1 gate.
# - Always install CORSMiddleware once enabled, even if origins env is empty.
#   When empty, we fall back to ["*"] so preflight never 400s in dev/tests.
# - Defaults (methods/headers) remain safe.

from __future__ import annotations

import os
from typing import List, Tuple

from starlette.middleware.cors import CORSMiddleware


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
            val = int(float(raw.strip()))
            return val if val >= 0 else default
    except Exception:
        return default


def _csv_env(name: str) -> List[str]:
    raw = os.getenv(name) or ""
    parts = [p.strip() for p in raw.replace(";", ",").replace(":", ",").split(",")]
    return [p for p in parts if p]


def cors_enabled() -> bool:
    return _bool_env("CORS_ENABLED", False)


def cors_config() -> Tuple[List[str], List[str], List[str], bool, int]:
    origins = _csv_env("CORS_ALLOW_ORIGINS")
    methods = [m.upper() for m in _csv_env("CORS_ALLOW_METHODS")] or ["GET", "POST", "OPTIONS"]
    headers = _csv_env("CORS_ALLOW_HEADERS") or ["*"]
    creds = _bool_env("CORS_ALLOW_CREDENTIALS", False)
    max_age = _int_env("CORS_MAX_AGE", 600)
    return origins, methods, headers, creds, max_age


def install_cors(app) -> None:
    if not cors_enabled():
        return
    origins, methods, headers, creds, max_age = cors_config()
    # Fallback to "*" when no explicit origins are provided (prevents 400 preflight in dev/tests).
    allow_origins = origins if origins else ["*"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_methods=methods,
        allow_headers=headers,
        allow_credentials=creds,
        max_age=max_age,
    )

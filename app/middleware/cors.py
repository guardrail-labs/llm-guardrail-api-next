# app/middleware/cors.py
# Summary (PR-K CORS fix):
# - Keep CORS behind CORS_ENABLED=1.
# - Preflight previously returned 400 when no Access-Control-Request-Headers was sent
#   and specific allow headers were configured. We now always allow "*"
#   for request headers to avoid that trap in dev/tests.
# - If no origins are provided, use allow_origin_regex=".*" so simple requests
#   echo the Origin and never 400, while remaining opt-in via CORS_ENABLED.

from __future__ import annotations

import os
from typing import List, Tuple, Optional

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


def cors_config() -> Tuple[List[str], List[str], bool, int]:
    origins = _csv_env("CORS_ALLOW_ORIGINS")
    methods = [m.upper() for m in _csv_env("CORS_ALLOW_METHODS")] or ["GET", "POST", "OPTIONS"]
    creds = _bool_env("CORS_ALLOW_CREDENTIALS", False)
    max_age = _int_env("CORS_MAX_AGE", 600)
    return origins, methods, creds, max_age


def install_cors(app) -> None:
    if not cors_enabled():
        return
    origins, methods, creds, max_age = cors_config()

    # Always allow all request headers to prevent 400 preflights when the client
    # doesn't send Access-Control-Request-Headers in tests/dev.
    allow_headers = ["*"]

    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_methods=methods,
            allow_headers=allow_headers,
            allow_credentials=creds,
            max_age=max_age,
        )
    else:
        # No explicit origins: accept any origin (echo) via regex.
        app.add_middleware(
            CORSMiddleware,
            allow_origin_regex=".*",
            allow_methods=methods,
            allow_headers=allow_headers,
            allow_credentials=creds,
            max_age=max_age,
        )

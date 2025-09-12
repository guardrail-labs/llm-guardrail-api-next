# app/middleware/cors.py
# Summary (PR-K final CORS fix):
# - Always install CORSMiddleware at app startup with safe, permissive defaults.
# - This avoids timing issues where env vars are set after the app module is imported.
# - Explicit env can still narrow the policy when present.
#
# Behavior:
# - If CORS_ALLOW_ORIGINS is set -> allow only those origins.
# - Else -> allow any origin via allow_origin_regex=".*" (echoes request Origin).
# - Methods default to GET/POST/OPTIONS; headers default to "*"; creds default False.

from __future__ import annotations

import os
from typing import List

from starlette.middleware.cors import CORSMiddleware


def _csv_env(name: str) -> List[str]:
    raw = os.getenv(name) or ""
    parts = [p.strip() for p in raw.replace(";", ",").replace(":", ",").split(",")]
    return [p for p in parts if p]


def _methods_env() -> List[str]:
    vals = _csv_env("CORS_ALLOW_METHODS")
    return [m.upper() for m in vals] if vals else ["GET", "POST", "OPTIONS"]


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
        v = int(float(raw.strip()))
        return v if v >= 0 else default
    except Exception:
        return default


def install_cors(app) -> None:
    origins = _csv_env("CORS_ALLOW_ORIGINS")
    methods = _methods_env()
    allow_headers = ["*"]  # prevent 400 preflights when client omits ACRH
    allow_credentials = _bool_env("CORS_ALLOW_CREDENTIALS", False)
    max_age = _int_env("CORS_MAX_AGE", 600)

    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_methods=methods,
            allow_headers=allow_headers,
            allow_credentials=allow_credentials,
            max_age=max_age,
        )
    else:
        # No explicit origins -> accept any origin (echo) via regex.
        app.add_middleware(
            CORSMiddleware,
            allow_origin_regex=".*",
            allow_methods=methods,
            allow_headers=allow_headers,
            allow_credentials=allow_credentials,
            max_age=max_age,
        )

from __future__ import annotations

import os
from typing import List

from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware


def _truthy(v: object) -> bool:
    return str(v).strip().lower() in {"1", "true", "yes", "on"}


def _split_csv(env_name: str, default: str = "") -> List[str]:
    raw = os.getenv(env_name, default)
    if not raw:
        return []
    return [x.strip() for x in raw.split(",") if x.strip()]


def install_cors(app: FastAPI) -> None:
    """
    Enable Starlette's CORS middleware when CORS_ENABLED is truthy.
    Env:
      CORS_ENABLED=1
      CORS_ALLOW_ORIGINS=http://example.com,http://localhost:3000
      CORS_ALLOW_METHODS=GET,POST,OPTIONS
      CORS_ALLOW_HEADERS=Content-Type,Authorization
      CORS_ALLOW_CREDENTIALS=1
      CORS_MAX_AGE=600
    """
    if not _truthy(os.getenv("CORS_ENABLED", "0")):
        return

    allow_origins = _split_csv("CORS_ALLOW_ORIGINS")
    allow_methods = _split_csv("CORS_ALLOW_METHODS") or ["*"]
    allow_headers = _split_csv("CORS_ALLOW_HEADERS") or ["*"]

    allow_credentials = _truthy(os.getenv("CORS_ALLOW_CREDENTIALS", "0"))
    try:
        max_age = int(os.getenv("CORS_MAX_AGE", "600"))
        if max_age < 0:
            max_age = 0
    except Exception:
        max_age = 600

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allow_origins or ["*"],
        allow_credentials=allow_credentials,
        allow_methods=allow_methods,
        allow_headers=allow_headers,
        max_age=max_age,
    )

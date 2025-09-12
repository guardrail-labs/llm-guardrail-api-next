# app/middleware/compression.py
# Summary (PR-V): Optional gzip compression via Starlette's GZipMiddleware.
# - Controlled by env:
#     COMPRESSION_ENABLED          (default: 0 -> disabled)
#     COMPRESSION_MIN_SIZE_BYTES   (default: 500)
# - No behavior change unless explicitly enabled.

from __future__ import annotations

from fastapi import FastAPI
from starlette.middleware.gzip import GZipMiddleware

from app.services.config_sanitizer import get_bool, get_int


def _enabled() -> bool:
    return get_bool("COMPRESSION_ENABLED", default=False)


def _min_size() -> int:
    # Clamp to >= 0; very small sizes can be wasteful but allowed for tests.
    return get_int("COMPRESSION_MIN_SIZE_BYTES", default=500, min_value=0)


def install_compression(app: FastAPI) -> None:
    if not _enabled():
        return
    app.add_middleware(GZipMiddleware, minimum_size=_min_size())

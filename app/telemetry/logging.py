"""Structured request logging (JSON) that respects X-Request-ID."""
from __future__ import annotations

import json
import logging
import uuid
from typing import Any, Dict

from fastapi import FastAPI, Request

from app.telemetry.tracing import get_request_id

_LOGGER_NAME = "guardrail"


def setup_logging(app: FastAPI) -> None:
    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(logging.INFO)

    @app.middleware("http")
    async def json_access_log(request: Request, call_next):
        # Prefer the RequestIDMiddleware value; fall back to caller header; finally generate.
        rid = get_request_id() or request.headers.get("X-Request-ID") or str(uuid.uuid4())

        response = await call_next(request)

        # IMPORTANT: do NOT set/overwrite X-Request-ID here.
        # RequestIDMiddleware is the single source of truth for the response header.

        record: Dict[str, Any] = {
            "event": "guardrail_request",
            "request_id": rid,
            "method": request.method,
            "path": str(request.url.path),
            "status_code": response.status_code,
        }
        try:
            logger.info(json.dumps(record, ensure_ascii=False))
        except Exception:
            # Logging must never break the response path
            pass

        return response

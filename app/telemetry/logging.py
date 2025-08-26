import json
import logging
from uuid import uuid4

from fastapi import FastAPI, Request


def setup_logging(app: FastAPI) -> None:
    """
    - Adds a request-id to every response as X-Request-ID
    - Emits a single JSON log for /guardrail requests
    """
    logger = logging.getLogger("guardrail")
    logger.setLevel(logging.INFO)

    # Avoid duplicate handlers if build_app() is called more than once in tests
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)

    @app.middleware("http")
    async def request_id_and_logging(request: Request, call_next):
        rid = str(uuid4())
        request.state.request_id = rid

        response = await call_next(request)
        response.headers["X-Request-ID"] = rid

        if request.url.path == "/guardrail":
            try:
                payload = {
                    "event": "guardrail_request",
                    "request_id": rid,
                    "method": request.method,
                    "path": str(request.url.path),
                    "status_code": response.status_code,
                }
                logger.info(json.dumps(payload))
            except Exception:
                # Logging must never break the request
                pass

        return response

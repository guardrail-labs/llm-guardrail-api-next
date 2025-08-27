"""Global JSON error handling with stable error codes and request correlation."""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.telemetry.tracing import get_request_id

# Map common HTTP statuses to stable machine-readable codes
_STATUS_TO_CODE = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    413: "payload_too_large",
    415: "unsupported_media_type",
    422: "validation_error",
    429: "rate_limited",
}


def _envelope(
    *,
    detail: str,
    status: int,
    code: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> JSONResponse:
    rid = get_request_id() or ""
    body: Dict[str, Any] = {
        "detail": detail,
        "code": code or _STATUS_TO_CODE.get(status, "error"),
        "request_id": rid,
    }
    if extra:
        body.update(extra)
    resp = JSONResponse(status_code=status, content=body)
    if rid and "X-Request-ID" not in resp.headers:
        resp.headers["X-Request-ID"] = rid
    return resp


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(StarletteHTTPException)
    async def http_exc_handler(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        # Honor the given status and detail, wrap with a code.
        detail = exc.detail if isinstance(exc.detail, str) else "HTTP error"
        code = _STATUS_TO_CODE.get(exc.status_code, "error")
        return _envelope(detail=detail, status=exc.status_code, code=code)

    @app.exception_handler(RequestValidationError)
    async def validation_exc_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
        return _envelope(
            detail="Validation failed",
            status=422,
            code="validation_error",
            extra={"errors": exc.errors()},
        )

    @app.exception_handler(Exception)
    async def unhandled_exc_handler(_: Request, __: Exception) -> JSONResponse:
        # Do not leak internals; logs already have the details with request_id
        return _envelope(
            detail="Internal server error", status=500, code="internal_error"
        )

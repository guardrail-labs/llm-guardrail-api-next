"""Global JSON error handling with stable error codes and request correlation."""

from __future__ import annotations

from typing import Any, Dict, Optional
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.runtime.arm import current_guardrail_mode
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


def _rid_from_request(request: Request) -> str:
    """Best-effort request id:
    1) context var set by RequestIDMiddleware
    2) inbound header from client
    3) new UUID4
    """
    return get_request_id() or request.headers.get("X-Request-ID") or str(uuid4())


def _json_error(
    request: Request,
    *,
    detail: str,
    status: int,
    code: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> JSONResponse:
    rid = _rid_from_request(request)
    body: Dict[str, Any] = {
        "detail": detail,
        "code": code or _STATUS_TO_CODE.get(status, "error"),
        "request_id": rid,
    }
    if extra:
        body.update(extra)
    resp = JSONResponse(status_code=status, content=body)
    resp.headers["X-Request-ID"] = rid

    if "X-Guardrail-Mode" not in resp.headers:
        try:
            mode = current_guardrail_mode()
            if not isinstance(mode, str):
                mode = getattr(mode, "value", str(mode))
        except Exception:
            mode = "normal"
        resp.headers["X-Guardrail-Mode"] = mode
    return resp


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(StarletteHTTPException)
    async def http_exc_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        detail = exc.detail if isinstance(exc.detail, str) else "HTTP error"
        code = _STATUS_TO_CODE.get(exc.status_code, "error")
        return _json_error(request, detail=detail, status=exc.status_code, code=code)

    @app.exception_handler(RequestValidationError)
    async def validation_exc_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        return _json_error(
            request,
            detail="Validation failed",
            status=422,
            code="validation_error",
            extra={"errors": exc.errors()},
        )

    @app.exception_handler(Exception)
    async def unhandled_exc_handler(request: Request, __: Exception) -> JSONResponse:
        # Do not leak internals; logs already contain details correlated by request_id.
        return _json_error(
            request,
            detail="Internal server error",
            status=500,
            code="internal_error",
        )

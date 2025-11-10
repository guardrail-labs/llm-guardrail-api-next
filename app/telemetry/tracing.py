# app/telemetry/tracing.py
from __future__ import annotations

import logging
import os
from types import TracebackType
from typing import Any, Awaitable, Callable, Optional, Type

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

log = logging.getLogger(__name__)

# ----------------------------- No-op tracing shim -----------------------------

class _NoopSpan:
    def set_attribute(self, *_: Any, **__: Any) -> None:
        return

    def get_span_context(self) -> Any:
        class _Ctx:
            is_valid = False
            trace_id = 0
        return _Ctx()

class _NoopTracer:
    def start_span(self, _name: str) -> _NoopSpan:
        return _NoopSpan()

class _UseSpanCtx:
    def __init__(self, span: _NoopSpan, *_: Any, **__: Any) -> None:
        self._span = span

    def __enter__(self) -> _NoopSpan:
        return self._span

    def __exit__(
        self,
        exc_type: Type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        return None

class _NoopTrace:
    """Subset of opentelemetry.trace used by this middleware."""

    def get_tracer(self, _name: str) -> _NoopTracer:
        return _NoopTracer()

    def use_span(self, span: _NoopSpan, *args: Any, **kwargs: Any) -> _UseSpanCtx:
        return _UseSpanCtx(span, *args, **kwargs)

# --------------------------------- Middleware ---------------------------------

RequestHandler = Callable[[Request], Awaitable[Response]]

class TracingMiddleware(BaseHTTPMiddleware):
    """
    Lightweight optional OpenTelemetry wiring.

    - If OTEL_ENABLED is not truthy, this is a no-op.
    - If opentelemetry packages are not installed, we log a warning and proceed
      with tracing disabled.
    - We import OTel lazily at runtime to keep imports optional and avoid mypy
      issues.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        self.enabled: bool = _truthy(os.getenv("OTEL_ENABLED", "false"))
        self._initialized: bool = False
        self._trace: Any | None = None

    async def dispatch(self, request: Request, call_next: RequestHandler) -> Response:
        if not self.enabled:
            return await call_next(request)

        if not self._initialized:
            self._initialized = self._ensure_tracer_provider()

        if not self._initialized or self._trace is None:
            return await call_next(request)

        tracer = self._trace.get_tracer("llm-guardrail")
        route = request.url.path
        peer_ip = request.client.host if request.client else "unknown"

        with self._trace.use_span(tracer.start_span(route), end_on_exit=True) as span:
            span.set_attribute("http.method", request.method)
            span.set_attribute("http.route", route)
            span.set_attribute("net.peer.ip", peer_ip)
            response = await call_next(request)
            span.set_attribute("http.status_code", response.status_code)
        return response

    def _ensure_tracer_provider(self) -> bool:
        """
        Try to configure OTEL. If not installed, log a warning and report initialized=True
        so callers can proceed with tracing disabled (self._trace stays None).
        """
        try:  # pragma: no cover
            from opentelemetry import trace as _trace
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor
        except Exception:
            log.warning("opentelemetry is not installed; tracing disabled.")
            return True

        endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
        service_name = os.getenv("OTEL_SERVICE_NAME", "llm-guardrail-api")

        try:  # pragma: no cover
            resource = Resource.create({"service.name": service_name})
            provider = TracerProvider(resource=resource)
            if endpoint:
                exporter = OTLPSpanExporter(endpoint=endpoint)
                processor = BatchSpanProcessor(exporter)
                provider.add_span_processor(processor)
            _trace.set_tracer_provider(provider)
            self._trace = _trace
            return True
        except Exception as e:
            log.warning(
                "Failed to initialize OpenTelemetry provider; tracing disabled. %s",
                e,
            )
            self._trace = None
            return True

def _truthy(val: object) -> bool:
    return str(val).strip().lower() in {"1", "true", "yes", "on"}

# ---- simple adapters used elsewhere -----------------------------------------

def get_request_id() -> Optional[str]:
    """
    Thin wrapper so other modules can import from here without caring
    where the request-id is actually implemented.
    """
    try:
        from app.middleware.request_id import get_request_id as _get
        rid = _get()
        return str(rid) if rid is not None else None
    except Exception:
        return None

def get_trace_id() -> Optional[str]:
    """
    Return current OpenTelemetry trace id as 32-char hex if available.
    Safe to call even when OTEL is not installed or no span is active.
    """
    try:  # pragma: no cover
        from opentelemetry import trace as _trace
        span = _trace.get_current_span()
        if span is None:
            return None
        ctx = span.get_span_context()
        if getattr(ctx, "is_valid", False):
            trace_id_int = getattr(ctx, "trace_id", 0)
            if isinstance(trace_id_int, int) and trace_id_int:
                return f"{trace_id_int:032x}"
        return None
    except Exception:
        return None

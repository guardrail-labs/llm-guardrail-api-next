# app/telemetry/tracing.py
from __future__ import annotations

import logging
import os
from typing import Any, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.types import ASGIApp

log = logging.getLogger(__name__)


# ----------------------------- No-op tracing shim -----------------------------

class _NoopSpan:
    def set_attribute(self, *_: Any, **__: Any) -> None:  # noqa: D401
        """No-op attribute setter."""
        return

    def get_span_context(self) -> Any:
        # Mimic OTEL SpanContext shape enough for get_trace_id()
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

    def __exit__(self, exc_type, exc, tb) -> None:
        # Do not suppress exceptions
        return False


class _NoopTrace:
    """Subset of opentelemetry.trace used by this middleware."""

    def get_tracer(self, _name: str) -> _NoopTracer:
        return _NoopTracer()

    def use_span(self, span: _NoopSpan, *args: Any, **kwargs: Any) -> _UseSpanCtx:
        return _UseSpanCtx(span, *args, **kwargs)


# --------------------------------- Middleware ---------------------------------

class TracingMiddleware(BaseHTTPMiddleware):
    """
    Lightweight optional OpenTelemetry wiring.

    - If OTEL_ENABLED is not truthy, this is a no-op.
    - If opentelemetry packages are not installed, we install a no-op tracer and continue.
    - We import OTel lazily at runtime to keep imports optional and avoid mypy issues.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        self.enabled = _truthy(os.getenv("OTEL_ENABLED", "false"))
        self._initialized = False
        self._trace: Any = None  # set on init if libs are available

    async def dispatch(self, request: Request, call_next):
        if not self.enabled:
            return await call_next(request)

        # Lazy init to avoid side effects during import time.
        if not self._initialized:
            self._initialized = self._ensure_tracer_provider()

        if not self._initialized or self._trace is None:
            # Tracing unavailable; proceed normally.
            return await call_next(request)

        tracer = self._trace.get_tracer("llm-guardrail")
        route = request.url.path
        peer_ip = request.client.host if request.client else "unknown"

        # Minimal span around the request
        with self._trace.use_span(tracer.start_span(route), end_on_exit=True) as span:
            span.set_attribute("http.method", request.method)
            span.set_attribute("http.route", route)
            span.set_attribute("net.peer.ip", peer_ip)
            response = await call_next(request)
            span.set_attribute("http.status_code", response.status_code)
        return response

    def _ensure_tracer_provider(self) -> bool:
        """
        Try to configure OTEL. If not installed, fall back to a no-op tracer,
        log a warning, and report initialized=True so callers can proceed.
        """
        try:  # pragma: no cover
            from opentelemetry import trace as _trace
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor
        except Exception:
            # OTEL not available; install no-op shim so tracing calls are safe.
            log.warning("OpenTelemetry not installed; using no-op tracer.")
            self._trace = _NoopTrace()
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
            log.warning("Failed to initialize OpenTelemetry provider; using no-op tracer. %s", e)
            self._trace = _NoopTrace()
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

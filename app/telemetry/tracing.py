from __future__ import annotations

import contextvars
import os
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.types import ASGIApp

# We keep imports optional so tests/projects without OTel still pass.
try:  # pragma: no cover
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    _OTEL_AVAILABLE = True
except Exception:  # pragma: no cover
    trace = None  # type: ignore[assignment]
    OTLPSpanExporter = None  # type: ignore[assignment]
    Resource = None  # type: ignore[assignment]
    TracerProvider = None  # type: ignore[assignment]
    BatchSpanProcessor = None  # type: ignore[assignment]
    _OTEL_AVAILABLE = False


_REQUEST_ID = contextvars.ContextVar[Optional[str]]("request_id", default=None)


def get_request_id() -> Optional[str]:
    return _REQUEST_ID.get()


class TracingMiddleware(BaseHTTPMiddleware):
    """
    Lightweight OTel wiring. If opentelemetry* packages are not installed or
    OTEL_ENABLED is not truthy, this becomes a no-op.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        self.enabled = _truthy(os.getenv("OTEL_ENABLED", "false"))
        self._initialized = False

    async def dispatch(self, request: Request, call_next):
        if not self.enabled:
            return await call_next(request)

        # Lazy init to avoid side effects during import time.
        if not self._initialized:
            self._initialized = self._ensure_tracer_provider()

        if not _OTEL_AVAILABLE:
            return await call_next(request)

        tracer = trace.get_tracer("llm-guardrail")
        route = request.url.path

        # Add a basic Server-Timing hint even without collectors.
        # This is harmless and useful to eyeball timings in dev tools.
        response = None
        with tracer.start_as_current_span(route) as span:  # type: ignore[attr-defined]
            # Tag a few request attributes
            span.set_attribute("http.method", request.method)  # type: ignore[attr-defined]
            span.set_attribute("http.route", route)  # type: ignore[attr-defined]
            span.set_attribute(
                "net.peer.ip",
                (request.client.host if request.client else "unknown"),
            )  # type: ignore[attr-defined]
            response = await call_next(request)
            span.set_attribute("http.status_code", response.status_code)  # type: ignore[attr-defined]
        return response

    def _ensure_tracer_provider(self) -> bool:
        if not _OTEL_AVAILABLE:
            return False
        endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
        service_name = os.getenv("OTEL_SERVICE_NAME", "llm-guardrail-api")
        try:  # pragma: no cover
            resource = Resource.create({"service.name": service_name})
            provider = TracerProvider(resource=resource)
            if endpoint:
                exporter = OTLPSpanExporter(endpoint=endpoint)
                processor = BatchSpanProcessor(exporter)
                provider.add_span_processor(processor)
            trace.set_tracer_provider(provider)  # type: ignore[attr-defined]
            return True
        except Exception:
            return False


def _truthy(val: object) -> bool:
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


from __future__ import annotations

import importlib
import logging
import os
from typing import Any, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.types import ASGIApp


logger = logging.getLogger("app.telemetry")


class TracingMiddleware(BaseHTTPMiddleware):
    """
    Lightweight optional OpenTelemetry wiring.

    - If OTEL_ENABLED is not truthy, this is a no-op.
    - If opentelemetry packages are not installed, this is a no-op.
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
        # Import here to keep dependencies optional and avoid static type noise.
        try:  # pragma: no cover
            from opentelemetry import trace as _trace
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor
        except Exception:
            logger.warning(
                "OTel enabled but opentelemetry is not installed; tracing disabled"
            )
            self._trace = None
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
        except Exception:
            return False


def _truthy(val: object) -> bool:
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


# Optional helper to expose current trace id (if any) without requiring callers
# to import OpenTelemetry directly. Returns a 32-character hex string or None.
def get_trace_id() -> Optional[str]:
    try:  # pragma: no cover - opentelemetry is optional
        from opentelemetry.trace import get_current_span
    except Exception:
        return None

    try:
        span = get_current_span()
        ctx = span.get_span_context()  # type: ignore[assignment]
        trace_id = getattr(ctx, "trace_id", 0)
        if not trace_id:
            return None
        return f"{trace_id:032x}"
    except Exception:
        return None


# ---------------------------------------------------------------------
# Back-compat shim: some modules used to import get_request_id from here.
# We proxy to app.middleware.request_id at runtime without static imports.
# ---------------------------------------------------------------------
def get_request_id() -> Optional[str]:
    mod = importlib.import_module("app.middleware.request_id")
    func = getattr(mod, "get_request_id", None)
    if callable(func):
        rid = func()
        return str(rid) if rid is not None else None
    return None

from __future__ import annotations

from typing import Any, Awaitable, Callable

from prometheus_client import Counter
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

RequestHandler = Callable[[Request], Awaitable[Response]]

HTTP_STATUS = Counter(
    "guardrail_http_status_total",
    "HTTP responses by endpoint and status code",
    labelnames=("endpoint", "status"),
)


def _endpoint_name(req: Request) -> str:
    """Prefer the resolved route pattern (e.g., '/guardrail/evaluate'). Fallback to raw path."""
    route: Any = req.scope.get("route")
    if route is not None:
        path_attr = getattr(route, "path", None)
        if isinstance(path_attr, str):
            return path_attr
    return str(req.url.path)


class HttpStatusMetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestHandler) -> Response:
        # Let routing resolve first so scope['route'] is available for the 2xx/4xx case.
        try:
            response = await call_next(request)
        except Exception:
            # On unhandled exception, derive label here (router may or may not have matched yet).
            endpoint = _endpoint_name(request)
            HTTP_STATUS.labels(endpoint=endpoint, status="500").inc()
            raise
        # Normal path: route resolved, so use the route pattern.
        endpoint = _endpoint_name(request)
        HTTP_STATUS.labels(endpoint=endpoint, status=str(response.status_code)).inc()
        return response

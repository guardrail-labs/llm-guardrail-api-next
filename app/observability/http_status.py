from __future__ import annotations

from typing import Awaitable, Callable

from prometheus_client import Counter
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

HTTP_STATUS = Counter(
    "guardrail_http_status_total",
    "HTTP responses by endpoint and status code",
    labelnames=("endpoint", "status"),
)


def _endpoint_name(req: Request) -> str:
    # Prefer the route pattern (e.g., /guardrail/evaluate) to avoid path explosions
    route = req.scope.get("route")
    if route is not None and getattr(route, "path", None):
        return route.path  # type: ignore[attr-defined]
    # Fallback to raw path
    return req.url.path


class HttpStatusMetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        endpoint = _endpoint_name(request)
        try:
            response = await call_next(request)
        except Exception:
            # Count as 500 on unhandled exception, then re-raise
            HTTP_STATUS.labels(endpoint=endpoint, status="500").inc()
            raise
        HTTP_STATUS.labels(endpoint=endpoint, status=str(response.status_code)).inc()
        return response


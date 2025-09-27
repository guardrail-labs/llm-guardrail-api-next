from __future__ import annotations

from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route
from starlette.testclient import TestClient

from app.main import create_app

_TRACEPARENT = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"


def _traceparent_app():
    app = create_app()

    async def handler(request: Request) -> Response:
        resp = Response("ok", media_type="text/plain")
        resp.headers["traceparent"] = _TRACEPARENT
        return resp

    app.router.routes.append(Route("/tp", handler, methods=["GET"]))
    return app


def test_downstream_traceparent_survives_middleware() -> None:
    with TestClient(_traceparent_app()) as client:
        response = client.get("/tp")
    assert response.status_code == 200
    tp = response.headers.get("traceparent", "")
    assert tp == _TRACEPARENT

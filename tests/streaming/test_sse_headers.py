from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.middleware.stream_sse_guard import SSEGuardMiddleware
from app.routes.stream_example import router as stream_router


def create_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(SSEGuardMiddleware)
    app.include_router(stream_router)
    return app


def test_sse_headers_present():
    app = create_app()
    client = TestClient(app)
    with client.stream("GET", "/stream/demo") as r:
        # Initial headers
        assert r.headers["content-type"].startswith("text/event-stream")
        assert "no-cache" in r.headers["cache-control"]
        assert r.headers.get("x-accel-buffering") == "no"
        assert r.headers.get("content-encoding") in (None, "")

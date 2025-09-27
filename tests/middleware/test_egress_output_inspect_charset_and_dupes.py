from __future__ import annotations

from fastapi import FastAPI
from starlette.responses import StreamingResponse
from starlette.testclient import TestClient

from app.middleware.egress_output_inspect import EgressOutputInspectMiddleware


def make_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(EgressOutputInspectMiddleware)
    return app


def test_streaming_preserves_charset() -> None:
    app = make_app()

    @app.get("/latin-stream")
    async def latin_stream() -> StreamingResponse:
        async def gen():
            yield "café"

        resp = StreamingResponse(gen(), media_type="text/plain; charset=latin-1")
        resp.charset = "latin-1"
        return resp

    client = TestClient(app)
    resp = client.get("/latin-stream")
    assert resp.status_code == 200
    ctype = resp.headers.get("content-type", "").lower()
    assert "charset=latin-1" in ctype
    assert resp.text == "café"


def test_streaming_no_duplicate_chunks() -> None:
    app = make_app()

    @app.get("/dup")
    async def dup() -> StreamingResponse:
        async def gen():
            yield "a"
            yield "b"

        return StreamingResponse(gen(), media_type="text/plain; charset=utf-8")

    client = TestClient(app)
    resp = client.get("/dup")
    assert resp.status_code == 200
    assert resp.text == "ab"

from __future__ import annotations

import asyncio
from typing import AsyncIterator, Iterator

import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.testclient import TestClient

from app.middleware.egress_output_inspect import EgressOutputInspectMiddleware


def _chunks_sync() -> Iterator[bytes]:
    yield b"data: hello\n\n"
    yield b"data: world\n\n"


async def _chunks_async() -> AsyncIterator[bytes]:
    yield b"data: a\n\n"
    await asyncio.sleep(0)
    yield b"data: b\n\n"


@pytest.fixture()
def client() -> Iterator[TestClient]:
    app = FastAPI()

    @app.get("/sse-demo")
    def sse_demo() -> StreamingResponse:
        response = StreamingResponse(_chunks_sync(), media_type="text/event-stream")
        response.headers["Content-Length"] = "123"
        return response

    @app.get("/stream-demo")
    def stream_demo() -> StreamingResponse:
        response = StreamingResponse(_chunks_async(), media_type="application/octet-stream")
        response.headers["Content-Length"] = "456"
        return response

    @app.get("/health")
    def health() -> JSONResponse:
        return JSONResponse({"status": "ok"})

    app.add_middleware(EgressOutputInspectMiddleware)

    with TestClient(app) as test_client:
        yield test_client


def test_sse_has_no_content_length(client: TestClient) -> None:
    response = client.get("/sse-demo")
    assert response.headers.get("Content-Type", "").startswith("text/event-stream")
    assert "Content-Length" not in response.headers


def test_generic_stream_no_content_length(client: TestClient) -> None:
    response = client.get("/stream-demo")
    assert response.status_code == 200
    assert "Content-Length" not in response.headers


def test_non_streaming_json_keeps_length_or_size_semantics(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    if "Content-Length" in response.headers:
        assert int(response.headers["Content-Length"]) >= 0

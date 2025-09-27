from __future__ import annotations

import asyncio

import pytest
from fastapi import FastAPI
from starlette.responses import StreamingResponse
from starlette.testclient import TestClient

from app.middleware.egress_output_inspect import EgressOutputInspectMiddleware


@pytest.fixture()
def make_app():
    def _factory():
        app = FastAPI()
        app.add_middleware(EgressOutputInspectMiddleware)
        return app

    return _factory


def test_two_chunk_no_dupe_utf8(make_app) -> None:
    app = make_app()

    async def gen():
        for chunk in (b"ab", b"cd"):
            await asyncio.sleep(0)
            yield chunk

    @app.get("/two")
    async def two():  # pragma: no cover - executed via client
        return StreamingResponse(gen(), media_type="text/plain; charset=utf-8")

    with TestClient(app) as client:
        response = client.get("/two")
    assert response.status_code == 200
    assert "content-length" not in {k.lower(): v for k, v in response.headers.items()}
    assert response.text == "abcd"


def test_markup_split_across_chunks_sets_flag(make_app) -> None:
    app = make_app()

    async def gen():
        yield b"<di"
        yield b"v>Hello"
        yield b"</di"
        yield b"v>"

    @app.get("/markup")
    async def markup():  # pragma: no cover - executed via client
        return StreamingResponse(gen(), media_type="text/plain; charset=utf-8")

    with TestClient(app) as client:
        response = client.get("/markup")
    assert response.status_code == 200
    flags = response.headers.get("X-Guardrail-Egress-Flags", "")
    assert "markup" in flags


def test_zwc_split_sets_flag(make_app) -> None:
    app = make_app()
    zwc = "\u200b".encode("utf-8")

    async def gen():
        yield b"A"
        yield zwc[:1]
        yield zwc[1:]
        yield b"B"

    @app.get("/zwc")
    async def zwc_route():  # pragma: no cover - executed via client
        return StreamingResponse(gen(), media_type="text/plain; charset=utf-8")

    with TestClient(app) as client:
        response = client.get("/zwc")
    assert response.status_code == 200
    flags = response.headers.get("X-Guardrail-Egress-Flags", "")
    assert "zwc" in flags
    assert response.text == "A\u200bB"


def test_binary_ct_skips_flags(make_app) -> None:
    app = make_app()

    async def gen():
        yield b"\x00\xff\x00\xff"

    @app.get("/bin")
    async def bin_route():  # pragma: no cover - executed via client
        return StreamingResponse(gen(), media_type="application/octet-stream")

    with TestClient(app) as client:
        response = client.get("/bin")
    assert response.status_code == 200
    flags = response.headers.get("X-Guardrail-Egress-Flags")
    assert not flags


def test_image_stream_skips_flags(make_app) -> None:
    app = make_app()

    async def gen():
        yield b"\x89PNG\r\n\x1a\n"
        yield b"chunk"

    @app.get("/png")
    async def png_route():  # pragma: no cover - executed via client
        return StreamingResponse(gen(), media_type="image/png")

    with TestClient(app) as client:
        response = client.get("/png")
    assert response.status_code == 200
    flags = response.headers.get("X-Guardrail-Egress-Flags")
    assert not flags


def test_sse_stream_has_no_content_length(make_app) -> None:
    app = make_app()

    async def gen():
        for chunk in (b"data: ping\n\n", b"data: pong\n\n"):
            await asyncio.sleep(0)
            yield chunk

    @app.get("/sse")
    async def sse_route():  # pragma: no cover - executed via client
        return StreamingResponse(gen(), media_type="text/event-stream")

    with TestClient(app) as client:
        response = client.get("/sse")
    assert response.status_code == 200
    headers = {k.lower(): v for k, v in response.headers.items()}
    assert "content-length" not in headers
    assert response.text.endswith("data: pong\n\n")

import asyncio

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse, StreamingResponse
from fastapi.testclient import TestClient


def _mk_app():
    app = FastAPI()
    from app.middleware.egress_redact import EgressRedactMiddleware

    app.add_middleware(EgressRedactMiddleware)

    @app.get("/sse")
    async def sse():
        async def gen():
            yield b"data: secret@email.com\n\n"
            await asyncio.sleep(0.01)
            yield b"data: still-streaming\n\n"

        return StreamingResponse(gen(), media_type="text/event-stream")

    @app.get("/normal")
    async def normal():
        return PlainTextResponse("contact me at secret@email.com")

    return app


def test_skip_on_streaming_sse(monkeypatch):
    monkeypatch.setenv("EGRESS_REDACT_MAX_BYTES", "1048576")
    monkeypatch.setenv("EGRESS_REDACT_ENABLED", "true")
    app = _mk_app()
    client = TestClient(app)

    response = client.get("/sse")
    assert response.status_code == 200
    assert response.headers.get("X-Redaction-Skipped") == "streaming"
    assert "secret@email.com" in response.text


def test_no_skip_on_normal(monkeypatch):
    monkeypatch.setenv("EGRESS_REDACT_ENABLED", "true")
    app = _mk_app()
    client = TestClient(app)

    response = client.get("/normal")
    assert response.status_code == 200
    assert response.headers.get("X-Redaction-Skipped") != "streaming"

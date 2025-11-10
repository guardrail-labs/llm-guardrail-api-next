from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from fastapi.testclient import TestClient


def test_big_body_streams_without_content_length(monkeypatch):
    monkeypatch.setenv("EGRESS_REDACT_WINDOW_BYTES", "4096")

    app = FastAPI()

    from app.middleware.egress_redact import EgressRedactMiddleware

    app.add_middleware(EgressRedactMiddleware)

    chunk = b"A" * (2 * 1024 * 1024)

    def gen():
        for index in range(0, len(chunk), 32768):
            yield chunk[index : index + 32768]

    @app.get("/big")
    def big_stream() -> StreamingResponse:
        return StreamingResponse(gen(), media_type="text/plain; charset=utf-8")

    client = TestClient(app)
    response = client.get("/big")
    assert response.status_code == 200
    assert "content-length" not in {key.lower(): value for key, value in response.headers.items()}

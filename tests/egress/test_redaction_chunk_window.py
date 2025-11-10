from __future__ import annotations

import asyncio

from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from fastapi.testclient import TestClient


def make_app(redact_target: str = "secretEmail@example.com"):
    app = FastAPI()

    from app.middleware.egress_redact import EgressRedactMiddleware

    app.add_middleware(EgressRedactMiddleware)

    @app.get("/split")
    async def split() -> StreamingResponse:
        target = redact_target
        prefix = target[: len(target) - 5].encode()
        suffix = target[len(target) - 5 :].encode()

        async def gen():
            yield b"prefix "
            yield prefix
            yield suffix
            yield b" suffix"

        return StreamingResponse(gen(), media_type="text/plain; charset=utf-8")

    @app.get("/sse")
    async def sse() -> StreamingResponse:
        async def gen():
            yield b"data: secretEmail@example.com\n\n"
            await asyncio.sleep(0.01)
            yield b"data: still-streaming\n\n"

        return StreamingResponse(gen(), media_type="text/event-stream")

    return app


def test_boundary_match_is_redacted(monkeypatch):
    monkeypatch.setenv("EGRESS_REDACT_WINDOW_BYTES", "64")
    monkeypatch.setenv("EGRESS_REDACT_ENABLED", "true")
    from app.services import policy_redact as policy_module
    from app.services.policy_redact import RedactRule

    monkeypatch.setattr(
        policy_module,
        "get_redact_rules",
        lambda: [
            RedactRule(
                "test-email",
                r"secretEmail@example\.com",
                "[REDACTED]",
                0,
            )
        ],
    )
    app = make_app()
    client = TestClient(app)

    response = client.get("/split")
    assert response.status_code == 200
    assert "secretEmail@example.com" not in response.text
    assert response.headers.get("X-Redaction-Mode") == "windowed"


def test_sse_still_skipped(monkeypatch):
    monkeypatch.setenv("EGRESS_REDACT_ENABLED", "true")
    app = make_app()
    client = TestClient(app)

    response = client.get("/sse")
    assert response.status_code == 200
    assert response.headers.get("X-Redaction-Skipped") == "streaming"

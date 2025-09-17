import asyncio

from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from fastapi.testclient import TestClient

from app.middleware.egress_redact import EgressRedactMiddleware
from app.services import policy_redact as pr
from app.services.policy_redact import RedactRule


def _streaming_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(EgressRedactMiddleware)

    async def generator():
        for chunk in [b"data: sk_test_ABCDEFGHIJK\n\n", b"data: keep\n\n"]:
            yield chunk
            await asyncio.sleep(0.01)

    @app.get("/sse")
    def sse():
        return StreamingResponse(generator(), media_type="text/event-stream")

    return app


def test_streaming_sse_passthrough(monkeypatch):
    monkeypatch.setenv("EGRESS_REDACT_ENABLED", "true")
    monkeypatch.setattr(
        pr,
        "get_redact_rules",
        lambda: [RedactRule("secret-key", r"sk_test_[A-Za-z0-9]+", "[X]")],
    )

    app = _streaming_app()
    client = TestClient(app)

    response = client.get("/sse", timeout=5)
    assert response.status_code == 200
    assert response.headers.get("content-type", "").startswith("text/event-stream")
    assert "sk_test_ABCDEFGHIJK" in response.text

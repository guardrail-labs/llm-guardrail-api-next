import asyncio

import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient
from starlette.responses import StreamingResponse

from app.main import app as main_app
from app.middleware import egress_guard

router = APIRouter()


@router.get("/test/stream-sse")
async def stream_sse():
    async def gen():
        # Deliberately split an email across chunks to test overlap
        yield b"data: hello a@g"
        await asyncio.sleep(0)  # yield control
        yield b"mail.com\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")


@pytest.fixture
def app():
    return main_app


@pytest.fixture
def client(app):
    return TestClient(app)


def test_streaming_redactor_disabled(client, monkeypatch, app):
    # Ensure feature is OFF; email should pass through
    monkeypatch.setenv("EGRESS_STREAMING_REDACT_ENABLED", "0")
    monkeypatch.setattr(egress_guard, "STREAMING_REDACT_ENABLED", False)
    # mount route once for this test app
    try:
        app.include_router(router)
    except Exception:
        pass
    r = client.get("/test/stream-sse", headers={"accept": "text/event-stream"})
    assert r.status_code == 200
    t = r.text
    assert "a@gmail.com" in t  # unredacted when disabled


def test_streaming_redactor_enabled(client, monkeypatch, app):
    monkeypatch.setenv("EGRESS_STREAMING_REDACT_ENABLED", "1")
    monkeypatch.setenv("EGRESS_STREAMING_OVERLAP_CHARS", "8")
    monkeypatch.setattr(egress_guard, "STREAMING_REDACT_ENABLED", True)
    monkeypatch.setattr(egress_guard, "STREAMING_OVERLAP_CHARS", 8)
    try:
        app.include_router(router)
    except Exception:
        pass
    r = client.get("/test/stream-sse", headers={"accept": "text/event-stream"})
    assert r.status_code == 200
    t = r.text
    # Email should be redacted using default egress redactions
    assert "[REDACTED-EMAIL]" in t
    # Streaming should not set content-length
    assert "content-length" not in {k.lower() for k in r.headers}
    # Content type remains SSE
    assert "text/event-stream" in r.headers.get("content-type", "").lower()

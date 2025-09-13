import asyncio
import re
from fastapi import APIRouter
from starlette.responses import StreamingResponse

router = APIRouter()


@router.get("/metrics/test/stream-sse")
async def stream_sse():
    async def gen():
        # split email across chunks to force cross-boundary redaction
        yield b"data: part1 a@g"
        await asyncio.sleep(0)
        yield b"mail.com part2\n\n"
    return StreamingResponse(gen(), media_type="text/event-stream")


def _get_stream_redactions_counter(client) -> float:
    m = client.get("/metrics")
    assert m.status_code == 200
    text = m.text
    pat = re.compile(r'(?m)^guardrail_egress_redactions_total\{[^}]*content_type="text/stream"[^}]*\}\s+([0-9]+(?:\.[0-9]+)?)$')
    match = pat.search(text)
    return float(match.group(1)) if match else 0.0


def test_streaming_redaction_increments_counter(client, monkeypatch, app):
    monkeypatch.setenv("EGRESS_STREAMING_REDACT_ENABLED", "1")
    monkeypatch.setenv("EGRESS_STREAMING_OVERLAP_CHARS", "8")
    # ensure router is mounted
    try:
        app.include_router(router)
    except Exception:
        pass

    before = _get_stream_redactions_counter(client)

    r = client.get("/metrics/test/stream-sse", headers={"accept": "text/event-stream"})
    assert r.status_code == 200
    # force body consumption so the generator completes and metrics are updated
    _ = r.text
    assert "text/event-stream" in r.headers.get("content-type", "").lower()
    assert r.headers.get("X-Guardrail-Streaming-Redactor") == "enabled"

    after = _get_stream_redactions_counter(client)
    assert after > before, f"counter did not increase (before={before}, after={after})"

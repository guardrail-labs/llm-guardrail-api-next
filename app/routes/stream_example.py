from __future__ import annotations

from typing import AsyncIterator

import anyio
from fastapi import APIRouter
from starlette.responses import StreamingResponse

from app.services.event_stream import EventStream
from app.services.stream_redactor import RedactorBoundaryWriter

router = APIRouter(prefix="/stream", tags=["stream"])


async def _gen() -> AsyncIterator[bytes]:
    es = EventStream(heartbeat_sec=0.5, retry_ms=1000)
    rbw = RedactorBoundaryWriter()

    # Send retry hint once
    yield es.retry()

    # Simulated producer loop
    send_tick = 0
    while send_tick < 5:
        for part in rbw.feed(b"Hello chunk %d.\n" % send_tick):
            yield es.frame(part.decode("utf-8"))
        send_tick += 1
        try:
            with anyio.move_on_after(0.5):
                await anyio.sleep(0.5)
            yield es.heartbeat()
        except Exception:
            break

    for part in rbw.flush():
        yield es.frame(part.decode("utf-8"))


@router.get("/demo")
async def stream_demo() -> StreamingResponse:
    resp = StreamingResponse(_gen(), media_type="text/event-stream")
    # Mark as SSE for middleware even if proxies strip content-type early
    resp.raw_headers.append((b"x-sse", b"1"))
    return resp

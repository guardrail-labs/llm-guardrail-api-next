from __future__ import annotations

import asyncio
from typing import AsyncIterator, Iterable

from fastapi import APIRouter
from starlette.responses import StreamingResponse

from app.services.event_stream import EventStream
from app.services.stream_redactor import RedactorBoundaryWriter

router = APIRouter()


async def _demo_stream() -> AsyncIterator[bytes]:
    writer = RedactorBoundaryWriter()
    payloads: Iterable[bytes] = (
        EventStream.frame({"message": "demo-start"}, event="message", id="1"),
        EventStream.heartbeat(),
        EventStream.frame("Streaming complete", event="message", id="2"),
    )
    for payload in payloads:
        for chunk in writer.feed(payload):
            yield chunk
        await asyncio.sleep(0)
    for chunk in writer.flush():
        yield chunk


@router.get("/stream/demo")
async def stream_demo() -> StreamingResponse:
    response = StreamingResponse(_demo_stream(), media_type="text/event-stream")
    response.headers["x-sse"] = "1"
    return response

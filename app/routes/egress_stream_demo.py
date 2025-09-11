from __future__ import annotations

from typing import AsyncIterator

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse

from app.middleware.stream_guard import wrap_stream
from app.services import runtime_flags as rf

router = APIRouter()


async def _chunker(text: str, n: int) -> AsyncIterator[str]:
    i = 0
    ln = len(text)
    while i < ln:
        yield text[i : i + n]
        i += n


async def _to_bytes(source: AsyncIterator[str], encoding: str = "utf-8"):
    async for s in source:
        yield s.encode(encoding)


@router.get("/demo/egress_stream")
async def demo_egress_stream(
    text: str = Query(...),
    chunk: int = Query(8, ge=1, le=4096),
):
    """
    Demo endpoint for the StreamingGuard. Splits `text` into `chunk`-sized
    pieces and streams them, applying streaming redactions when enabled.
    """
    src = _chunker(text, chunk)
    encoding = "utf-8"

    enabled = bool(rf.get("stream_egress_enabled") or False)
    if enabled:
        guard = wrap_stream(src, encoding=encoding)
        body = _to_bytes(guard, encoding=encoding)
        headers = {
            "X-Guardrail-Streaming": "1",
            # Redaction/deny counts are not known until consumed by client.
            # This demo keeps headers simple.
        }
    else:
        body = _to_bytes(src, encoding=encoding)
        headers = {"X-Guardrail-Streaming": "0"}

    return StreamingResponse(body, headers=headers, media_type="application/octet-stream")

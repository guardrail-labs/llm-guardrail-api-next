from __future__ import annotations

from typing import AsyncIterator

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from app.middleware.stream_guard import wrap_stream
from app.services import runtime_flags

router = APIRouter(prefix="/demo", tags=["demo"])


@router.get("/egress_stream")
async def egress_stream(text: str = "", chunk: int = 5) -> StreamingResponse:
    """Demo streaming endpoint that applies StreamingGuard."""

    async def gen() -> AsyncIterator[str]:
        for i in range(0, len(text), chunk):
            yield text[i : i + chunk]

    headers = {
        "X-Guardrail-Streaming": "0",
        "X-Guardrail-Stream-Redactions": "0",
        "X-Guardrail-Stream-Denied": "0",
    }

    source: AsyncIterator[str | bytes] = gen()
    if runtime_flags.stream_egress_enabled():
        stream = await wrap_stream(source)
        pieces = [c async for c in stream]
        guard = getattr(stream, "guard", None)
        headers["X-Guardrail-Streaming"] = "1"
        headers["X-Guardrail-Stream-Redactions"] = str(getattr(guard, "redactions", 0))
        headers["X-Guardrail-Stream-Denied"] = (
            "1" if getattr(guard, "denied", False) else "0"
        )
        return StreamingResponse(
            (p for p in pieces),
            headers=headers,
            media_type="application/octet-stream",
        )

    return StreamingResponse(source, headers=headers, media_type="application/octet-stream")

from __future__ import annotations

from typing import AsyncIterator, List

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse

from app.middleware.stream_guard import PatTriplet, wrap_stream
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


def _precount_redactions(text: str, patterns: List[PatTriplet]) -> int:
    count = 0
    tmp = text
    for rx, _tag, repl in patterns:
        tmp, n = rx.subn(repl, tmp)
        count += int(n)
    return count


def _will_deny(text: str) -> bool:
    import re

    env_re = re.compile(
        r"-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----",
        re.S,
    )
    marker_re = re.compile(
        r"(?:-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----)"
    )
    return bool(env_re.search(text) or marker_re.search(text))


@router.get("/demo/egress_stream")
async def demo_egress_stream(
    text: str = Query(...),
    chunk: int = Query(8, ge=1, le=4096),
):
    """
    Demo endpoint for the StreamingGuard. Splits `text` into `chunk`-sized
    pieces and streams them, applying streaming redactions when enabled.
    """
    from app.services.policy import get_stream_redaction_patterns

    patterns: List[PatTriplet] = list(get_stream_redaction_patterns())
    src = _chunker(text, chunk)
    encoding = "utf-8"

    val = rf.get("stream_egress_enabled")
    enabled = True if val is None else bool(val)

    headers = {}
    if enabled:
        # Pre-count redactions to surface a header (tests expect this).
        redactions = _precount_redactions(text, patterns)

        deny_flag_val = rf.get("stream_guard_deny_on_private_key")
        deny_enabled = True if deny_flag_val is None else bool(deny_flag_val)
        deny_hdr = "1" if (_will_deny(text) and deny_enabled) else "0"

        headers.update(
            {
                "X-Guardrail-Streaming": "1",
                "X-Guardrail-Stream-Redactions": str(redactions),
                "X-Guardrail-Stream-Denied": deny_hdr,
            }
        )
        guard = wrap_stream(src, patterns, encoding=encoding)
        body = _to_bytes(guard, encoding=encoding)
    else:
        headers["X-Guardrail-Streaming"] = "0"
        body = _to_bytes(src, encoding=encoding)

    return StreamingResponse(
        body, headers=headers, media_type="application/octet-stream"
    )

from __future__ import annotations

import asyncio
import codecs
import re
from typing import AsyncIterator, Callable, Optional, Tuple

# Redaction = (compiled_pattern, replacement)
Redaction = Tuple[re.Pattern[str], str]


class StreamingRedactor:
    """
    Incremental UTF-8 safe streaming redactor with an overlap window to
    detect regex matches that cross chunk boundaries.

    Algorithm:
      - Maintain an incremental UTF-8 decoder and a tail buffer of the last
        `overlap_chars` characters.
      - For each incoming bytes chunk, decode incrementally, append to tail,
        and if buffer > overlap, emit `buffer[:-overlap]` after applying
        redactions; keep the last `overlap` chars as new tail.
      - On flush, decode any remaining bytes and emit the final tail (redacted).

    'changed' counts how many emitted windows (including final tail) were altered.
    """

    def __init__(self, redactions: Tuple[Redaction, ...], overlap_chars: int = 2048) -> None:
        self._redactions = redactions
        self._overlap = max(0, int(overlap_chars))
        self._decoder = codecs.getincrementaldecoder("utf-8")()
        self._tail: str = ""
        self._changed: int = 0

    def _apply(self, s: str) -> str:
        out = s
        for pat, repl in self._redactions:
            new = pat.sub(repl, out)
            out = new
        return out

    def feed(self, chunk: bytes) -> str:
        text = self._decoder.decode(chunk)
        buf = self._tail + text

        if len(buf) <= self._overlap:
            self._tail = buf
            return ""

        emit = buf[:-self._overlap]
        kept = buf[-self._overlap:]

        redacted = self._apply(emit)
        if redacted != emit:
            self._changed += 1

        self._tail = kept
        return redacted

    def flush(self) -> str:
        tail_text = self._decoder.decode(b"", final=True)
        buf = self._tail + tail_text
        self._tail = ""

        redacted = self._apply(buf)
        if redacted != buf:
            self._changed += 1

        return redacted

    @property
    def changed(self) -> int:
        return self._changed


async def wrap_streaming_iterator(
    it: AsyncIterator[bytes],
    redactions: Tuple[Redaction, ...],
    *,
    overlap_chars: int = 2048,
    on_complete: Optional[Callable[[int], object]] = None,
) -> AsyncIterator[bytes]:
    """
    Wrap an async bytes iterator with streaming redaction.
    Yields bytes progressively; never sets content-length.

    on_complete(changed: int) is called exactly once after the final chunk is yielded.
    It may be synchronous or an async callable (coroutine function).
    """
    sr = StreamingRedactor(redactions, overlap_chars=overlap_chars)

    async for chunk in it:
        if not isinstance(chunk, (bytes, bytearray)):
            chunk = str(chunk).encode("utf-8")
        out = sr.feed(bytes(chunk))
        if out:
            yield out.encode("utf-8")

    final = sr.flush()
    if final:
        yield final.encode("utf-8")

    if on_complete:
        res = on_complete(sr.changed)
        if asyncio.iscoroutine(res):
            await res

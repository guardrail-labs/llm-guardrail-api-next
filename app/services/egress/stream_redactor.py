from __future__ import annotations

import codecs
import re
from typing import AsyncIterator, Tuple

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

    Notes:
      - Overlap ensures a pattern split across chunks eventually appears fully
        in a redaction window. Choose overlap >= longest sensitive token length.
    """

    def __init__(self, redactions: Tuple[Redaction, ...], overlap_chars: int = 2048) -> None:
        self._redactions = redactions
        self._overlap = max(0, int(overlap_chars))
        self._decoder = codecs.getincrementaldecoder("utf-8")()
        self._tail: str = ""
        self._changed: int = 0  # number of windows that were altered

    def _apply(self, s: str) -> str:
        out = s
        for pat, repl in self._redactions:
            new = pat.sub(repl, out)
            out = new
        return out

    def feed(self, chunk: bytes) -> str:
        # Decode next piece; incremental decoder handles UTF-8 boundaries safely.
        text = self._decoder.decode(chunk)
        buf = self._tail + text

        if len(buf) <= self._overlap:
            # Not enough to emit; keep accumulating.
            self._tail = buf
            return ""

        redacted = self._apply(buf)
        emit = redacted[:-self._overlap]
        self._tail = redacted[-self._overlap:]

        if emit != buf[:-self._overlap]:
            self._changed += 1

        return emit

    def flush(self) -> str:
        # Flush decoder residuals and final tail
        tail_text = self._decoder.decode(b"", final=True)
        buf = self._tail + tail_text
        self._tail = ""

        redacted = self._apply(buf)
        if redacted != buf:
            self._changed += 1

        return redacted

    @property
    def changed(self) -> int:
        """Number of emitted windows that were altered (approx redaction count)."""
        return self._changed


async def wrap_streaming_iterator(
    it: AsyncIterator[bytes],
    redactions: Tuple[Redaction, ...],
    *,
    overlap_chars: int = 2048,
) -> AsyncIterator[bytes]:
    """
    Wrap an async bytes iterator with streaming redaction.
    Yields bytes progressively; never sets content-length.
    """
    sr = StreamingRedactor(redactions, overlap_chars=overlap_chars)

    async for chunk in it:
        if not isinstance(chunk, (bytes, bytearray)):
            # Safety: coerce to bytes via UTF-8
            chunk = str(chunk).encode("utf-8")
        out = sr.feed(bytes(chunk))
        if out:
            yield out.encode("utf-8")

    final = sr.flush()
    if final:
        yield final.encode("utf-8")

    # Expose a changed count by attaching attribute (optional pattern).
    # Callers may inspect with getattr(iterator, "_stream_redactor_changed", 0)
    # but in our middleware we just use sr.changed synchronously.
    wrap_streaming_iterator._last_changed = sr.changed  # type: ignore[attr-defined]

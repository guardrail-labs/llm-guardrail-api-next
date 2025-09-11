from __future__ import annotations

from typing import AsyncIterator, List, Pattern, Tuple

from app.services import policy, runtime_flags
from app.telemetry import metrics as m


class StreamingGuard:
    """Boundary-aware streaming redaction wrapper."""

    def __init__(
        self,
        source: AsyncIterator[str | bytes],
        patterns: List[Tuple[Pattern[str], str, str]],
        lookback: int | None = None,
        deny_on_private_key: bool | None = None,
        *,
        encoding: str = "utf-8",
        flush_min_bytes: int | None = None,
    ) -> None:
        self._source = source
        self._patterns = patterns
        self._encoding = encoding
        self._lookback = (
            lookback if lookback is not None else runtime_flags.stream_guard_max_lookback_chars()
        )
        self._flush_min = (
            flush_min_bytes
            if flush_min_bytes is not None
            else runtime_flags.stream_guard_flush_min_bytes()
        )
        self._deny_private = (
            deny_on_private_key
            if deny_on_private_key is not None
            else runtime_flags.stream_guard_deny_on_private_key()
        )
        self._tail = ""
        self.redactions = 0
        self.denied = False

    def __aiter__(self) -> "StreamingGuard":
        return self

    async def __anext__(self) -> str:
        while True:
            if self.denied:
                raise StopAsyncIteration
            try:
                chunk = await self._source.__anext__()
            except StopAsyncIteration:
                if not self._tail:
                    raise
                out = self._tail
                self._tail = ""
                return out

            m.inc_stream_guard_chunks()
            s = (
                chunk.decode(self._encoding)
                if isinstance(chunk, (bytes, bytearray))
                else str(chunk)
            )
            self._tail += s

            if self._deny_private and "-----BEGIN PRIVATE KEY-----" in self._tail:
                self.denied = True
                self._tail = ""
                m.inc_stream_guard_denied()
                return "[STREAM BLOCKED]"

            for regex, tag, repl in self._patterns:
                self._tail, n = regex.subn(repl, self._tail)
                if n:
                    self.redactions += n
                    m.inc_redaction(tag, amount=float(n))

            if len(self._tail) > self._lookback:
                emit = self._tail[:-self._lookback]
                remain = self._tail[-self._lookback :]
                if self._flush_min and len(emit.encode(self._encoding)) < self._flush_min:
                    self._tail = emit + remain
                    continue
                self._tail = remain
                if emit:
                    return emit

    
async def wrap_stream(
    source: AsyncIterator[str | bytes], *, encoding: str = "utf-8"
) -> AsyncIterator[bytes]:
    """Wrap an async source with StreamingGuard and yield bytes."""

    guard = StreamingGuard(
        source,
        policy.get_stream_redaction_patterns(),
        encoding=encoding,
    )

    async def gen() -> AsyncIterator[bytes]:
        async for chunk in guard:
            yield chunk.encode(encoding)

    agen = gen()

    class _Wrapper:
        def __init__(self, inner: AsyncIterator[bytes], g: StreamingGuard) -> None:
            self._inner = inner
            self.guard = g

        def __aiter__(self) -> "_Wrapper":
            return self

        async def __anext__(self) -> bytes:
            return await self._inner.__anext__()

    return _Wrapper(agen, guard)

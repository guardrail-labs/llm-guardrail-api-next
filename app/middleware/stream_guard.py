from __future__ import annotations

import re
from typing import AsyncIterator, Iterable, List, Optional, Tuple, Union, Pattern, cast

# Streaming egress guard:
# - Scans/redacts as chunks stream.
# - Optionally denies on private key envelope.
# - Handles patterns that span chunk boundaries via a tail lookback buffer.
#
# IMPORTANT FIX:
# If lookback == 0, we now "emit everything" immediately (subject to flush_min),
# rather than slicing with -0 which previously buffered the entire stream.

StrOrBytes = Union[str, bytes]
PatTriplet = Tuple[Pattern[str], str, str]  # (regex, tag, replacement)

# Private key envelope across boundaries (deny if configured)
_PRIV_KEY_ENV_RE = re.compile(
    r"-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----", re.S
)

# -------- Optional deps (metrics, runtime flags, redaction patterns) ----------

def _noop(*_args, **_kwargs) -> None:  # ruff: disable=ARG001
    return None


try:
    # Metrics module is expected in this project.
    from app.telemetry import metrics as m  # type: ignore[attr-defined]
except Exception:  # pragma: no cover
    class _M:
        inc_redaction = staticmethod(_noop)
        inc_stream_guard_chunks = staticmethod(_noop)
        inc_stream_guard_denied = staticmethod(_noop)
    m = _M()  # type: ignore[assignment]


def _get_flag(name: str, default: int | bool) -> int | bool:
    try:
        from app.services import runtime_flags as rf  # type: ignore[attr-defined]

        # runtime_flags exposes get(name) -> value (per Codex card F)
        val = getattr(rf, "get")(name)  # type: ignore[misc]
        if val is None:
            return default
        return cast(int | bool, val)
    except Exception:  # pragma: no cover
        return default


def _load_stream_patterns() -> List[PatTriplet]:
    """
    Pull the redaction patterns from policy so streaming behavior matches
    non-streaming behavior. Falls back to a conservative subset if import fails.
    """
    try:
        from app.services.policy import (  # type: ignore[attr-defined]
            get_stream_redaction_patterns,
        )

        return list(get_stream_redaction_patterns())  # type: ignore[return-value]
    except Exception:  # pragma: no cover
        # Fallback minimal set (won't be hit in normal deployments).
        return [
            (re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"), "secrets:openai_key",
             "[REDACTED:OPENAI_KEY]"),
            (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "secrets:aws_key",
             "[REDACTED:AWS_ACCESS_KEY_ID]"),
            (re.compile(
                r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"
             ),
             "secrets:jwt", "[REDACTED:JWT]"),
        ]


# --------------------------------- Guard -------------------------------------


class StreamingGuard:
    def __init__(
        self,
        source: AsyncIterator[StrOrBytes],
        *,
        patterns: Optional[List[PatTriplet]] = None,
        lookback_chars: Optional[int] = None,
        flush_min_bytes: Optional[int] = None,
        deny_on_private_key: Optional[bool] = None,
        encoding: str = "utf-8",
    ) -> None:
        self._ait = source.__aiter__()
        self._encoding = encoding
        self._patterns = patterns or _load_stream_patterns()
        self._lookback = int(
            _get_flag("stream_guard_max_lookback_chars", 1024)
            if lookback_chars is None
            else lookback_chars
        )
        self._flush_min = int(
            _get_flag("stream_guard_flush_min_bytes", 0)
            if flush_min_bytes is None
            else flush_min_bytes
        )
        self._deny_on_pk = bool(
            _get_flag("stream_guard_deny_on_private_key", True)
            if deny_on_private_key is None
            else deny_on_private_key
        )
        self._tail: str = ""
        self._done = False
        self._denied = False
        self._block_yielded = False
        self._redactions = 0

    # -------------------------- Public properties --------------------------

    @property
    def redactions(self) -> int:
        return self._redactions

    @property
    def denied(self) -> bool:
        return self._denied

    # -------------------------- Async iterator API -------------------------

    def __aiter__(self) -> "StreamingGuard":
        return self

    async def __anext__(self) -> bytes:
        # If previously denied, yield the block token once and then stop.
        if self._denied and not self._block_yielded:
            self._block_yielded = True
            m.inc_stream_guard_denied()
            return b"[STREAM BLOCKED]"

        # If underlying source ended, flush remaining tail and stop.
        if self._done:
            if self._tail:
                out = self._tail
                self._tail = ""
                return out.encode(self._encoding)
            raise StopAsyncIteration

        # Pull chunks until we have something to emit or source ends.
        while True:
            try:
                chunk = await self._ait.__anext__()  # type: ignore[misc]
            except StopAsyncIteration:
                self._done = True
                # Final redaction pass before flushing remainder.
                self._apply_redactions()
                if self._denied and not self._block_yielded:
                    self._block_yielded = True
                    m.inc_stream_guard_denied()
                    return b"[STREAM BLOCKED]"
                if self._tail:
                    out = self._tail
                    self._tail = ""
                    return out.encode(self._encoding)
                raise

            m.inc_stream_guard_chunks()
            piece = chunk if isinstance(chunk, str) else chunk.decode(self._encoding)
            self._tail += piece

            # Apply redactions/deny to the entire tail buffer.
            self._apply_redactions()
            if self._denied and not self._block_yielded:
                self._block_yielded = True
                m.inc_stream_guard_denied()
                return b"[STREAM BLOCKED]"

            # ---- EMIT LOGIC (handles lookback == 0 correctly) ----
            if self._lookback <= 0:
                # Emit everything we have (subject to flush_min), keep no tail.
                if self._flush_min:
                    if len(self._tail.encode(self._encoding)) < self._flush_min:
                        # Not enough to flush yet; keep accumulating.
                        continue
                out = self._tail
                self._tail = ""
                if out:
                    return out.encode(self._encoding)
                # If empty (e.g., zero-length chunk), continue to next chunk.
                continue

            # Normal case: only emit when buffer exceeds lookback window.
            if len(self._tail) > self._lookback:
                emit = self._tail[:-self._lookback]
                remain = self._tail[-self._lookback :]
                if self._flush_min:
                    if len(emit.encode(self._encoding)) < self._flush_min:
                        # Accumulate until we meet the flush threshold.
                        self._tail = emit + remain
                        continue
                self._tail = remain
                if emit:
                    return emit.encode(self._encoding)
                # If emit empty (shouldn't happen here), keep reading.

    # ------------------------------- Helpers --------------------------------

    def _apply_redactions(self) -> None:
        """Apply deny/replace rules over the current tail buffer."""
        if self._deny_on_pk and _PRIV_KEY_ENV_RE.search(self._tail):
            self._denied = True
            return

        # Apply replacements; count matches; keep order stable.
        for rx, tag, repl in self._patterns:
            new_text, n = rx.subn(repl, self._tail)
            if n:
                self._tail = new_text
                self._redactions += n
                try:
                    m.inc_redaction(tag)
                except Exception:  # pragma: no cover
                    pass


# ----------------------------- Convenience API -------------------------------

def wrap_stream(
    source: AsyncIterator[StrOrBytes],
    *,
    patterns: Optional[List[PatTriplet]] = None,
    lookback_chars: Optional[int] = None,
    flush_min_bytes: Optional[int] = None,
    deny_on_private_key: Optional[bool] = None,
    encoding: str = "utf-8",
) -> StreamingGuard:
    """
    Wrap an async source iterator and return a StreamingGuard iterator.
    Callers can iterate and also inspect .redactions / .denied after consumption.
    """
    return StreamingGuard(
        source,
        patterns=patterns,
        lookback_chars=lookback_chars,
        flush_min_bytes=flush_min_bytes,
        deny_on_private_key=deny_on_private_key,
        encoding=encoding,
    )

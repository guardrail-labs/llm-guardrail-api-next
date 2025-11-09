from __future__ import annotations

import re
from typing import List

__all__ = ["RedactorBoundaryWriter"]

# Longest token we attempt to redact (covers API keys/JWTs) plus slack.
_MAX_PATTERN_LOOKBACK = 128

_SECRET_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"sk-[A-Za-z0-9]{16,}", re.IGNORECASE),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(r"(?:api|key|token)[=:]\s*[A-Za-z0-9_\-]{24,}"),
]


class RedactorBoundaryWriter:
    """Incrementally redact secrets without leaking across chunk boundaries."""

    def __init__(self, *, encoding: str = "utf-8") -> None:
        self._encoding = encoding
        self._buffer = ""

    def feed(self, chunk: bytes) -> list[bytes]:
        if not chunk:
            return []
        text = chunk.decode(self._encoding, "ignore")
        self._buffer += text
        emit_upto = max(len(self._buffer) - _MAX_PATTERN_LOOKBACK, 0)
        if emit_upto == 0:
            return []
        safe, self._buffer = self._buffer[:emit_upto], self._buffer[emit_upto:]
        return self._process(safe)

    def flush(self) -> list[bytes]:
        if not self._buffer:
            return []
        safe, self._buffer = self._buffer, ""
        return self._process(safe)

    def _process(self, text: str) -> list[bytes]:
        redacted = text
        for pattern in _SECRET_PATTERNS:
            redacted = pattern.sub("[REDACTED]", redacted)
        if redacted == "":
            return []
        return [redacted.encode(self._encoding)]

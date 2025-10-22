from __future__ import annotations

import re

_DEFAULT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"sk-[A-Za-z0-9]{16,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    re.compile(r"(?i)(password|api[_-]?key|secret)\s*[:=]\s*\S+"),
]


class RedactorBoundaryWriter:
    """
    Buffers partial tokens to avoid mid-chunk secret leaks. Emits only at safe boundaries.
    """

    def __init__(
        self, patterns: list[re.Pattern[str]] | None = None, max_hold_bytes: int = 4096
    ) -> None:
        self._buf = bytearray()
        self._max = max(128, max_hold_bytes)
        self._patterns = patterns or _DEFAULT_PATTERNS

    def feed(self, chunk: bytes) -> list[bytes]:
        self._buf.extend(chunk)
        out: list[bytes] = []

        # Emit on simple boundaries: newline or sentence-ish end
        last_nl = self._buf.rfind(b"\n")
        last_dot = self._buf.rfind(b". ")
        cut = max(last_nl, last_dot)

        if cut >= 0:
            emit = self._buf[: cut + 1]
            rem = self._buf[cut + 1 :]
            out.append(self._redact(bytes(emit)))
            self._buf = bytearray(rem)

        # Back-pressure: never hold unbounded
        if len(self._buf) > self._max:
            out.append(self._redact(bytes(self._buf)))
            self._buf.clear()

        return out

    def flush(self) -> list[bytes]:
        if not self._buf:
            return []
        out = [self._redact(bytes(self._buf))]
        self._buf.clear()
        return out

    def _redact(self, data: bytes) -> bytes:
        s = data.decode("utf-8", errors="replace")
        for pat in self._patterns:
            s = pat.sub("[REDACTED]", s)
        return s.encode("utf-8")

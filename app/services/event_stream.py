from __future__ import annotations

import json

__all__ = ["EventStream"]


class EventStream:
    """Helpers for framing Server-Sent Event payloads."""

    @staticmethod
    def frame(data: object, event: str | None = None, id: str | None = None) -> bytes:
        """Encode ``data`` into an SSE ``data:`` frame."""
        text = EventStream._coerce(data)
        lines: list[str] = []
        if id is not None:
            lines.append(f"id: {id}")
        if event is not None:
            lines.append(f"event: {event}")
        if text == "":
            lines.append("data:")
        else:
            for part in text.splitlines():
                lines.append(f"data: {part}")
            if text.endswith("\n"):
                lines.append("data:")
        return ("\n".join(lines) + "\n\n").encode("utf-8")

    @staticmethod
    def retry(delay_ms: int = 3000) -> bytes:
        """Suggest a reconnection delay to the SSE client."""
        delay = max(int(delay_ms), 0)
        return f"retry: {delay}\n\n".encode("utf-8")

    @staticmethod
    def heartbeat() -> bytes:
        """Emit a comment heartbeat frame."""
        return b":\n\n"

    @staticmethod
    def _coerce(value: object) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8", "ignore")
        if isinstance(value, str):
            return value
        return json.dumps(value, ensure_ascii=False)

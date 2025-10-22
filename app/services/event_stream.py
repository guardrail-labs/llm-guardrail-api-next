from __future__ import annotations


class EventStream:
    def __init__(self, heartbeat_sec: float = 15.0, retry_ms: int | None = 5000) -> None:
        self.heartbeat_sec = heartbeat_sec
        self.retry_ms = retry_ms

    def frame(
        self, data: str, *, event: str | None = None, id: str | None = None
    ) -> bytes:
        # Build SSE frame: optional event/id, then data lines, then blank line
        parts: list[str] = []
        if event:
            parts.append(f"event:{event}")
        if id:
            parts.append(f"id:{id}")
        for line in data.splitlines() or [""]:
            parts.append(f"data:{line}")
        return ("\n".join(parts) + "\n\n").encode("utf-8")

    def retry(self) -> bytes:
        if self.retry_ms is None:
            return b""
        return f"retry:{int(self.retry_ms)}\n\n".encode("utf-8")

    def heartbeat(self) -> bytes:
        # Comment line per SSE spec
        return b":\n\n"

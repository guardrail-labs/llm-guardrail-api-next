from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.routes.stream_example import router as stream_router


def test_stream_frames_and_heartbeats():
    app = FastAPI()
    app.include_router(stream_router)
    client = TestClient(app)
    chunks = []
    with client.stream("GET", "/stream/demo", timeout=5) as r:
        for i, line in enumerate(r.iter_lines()):
            chunk = line.decode("utf-8") if isinstance(line, bytes) else line
            chunks.append(chunk)
            if i > 10:
                break
    # Expect at least one heartbeat ":" and one data frame
    assert any(c == ":" for c in chunks)
    assert any(c.startswith("data:") for c in chunks)

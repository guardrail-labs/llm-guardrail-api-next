from fastapi.testclient import TestClient

from app.main import app
import app.services.runtime_flags as rf


client = TestClient(app)


def test_stream_guard_zero_lookback_still_streams(monkeypatch):
    # Force lookback=0 and no minimum flush to ensure immediate emits.
    orig_get = rf.get

    def fake_get(name: str):
        if name == "stream_guard_max_lookback_chars":
            return 0
        if name == "stream_guard_flush_min_bytes":
            return 0
        return orig_get(name)

    monkeypatch.setattr(rf, "get", fake_get, raising=True)

    text = "abcdefghijklmnopqrstuvwxyz"
    r = client.get("/demo/egress_stream", params={"text": text, "chunk": 3})
    assert r.status_code == 200
    # Route marks streaming when guard is active.
    assert r.headers.get("X-Guardrail-Streaming") == "1"
    # With no secrets in the payload, the stream should pass through intact.
    assert r.text == text

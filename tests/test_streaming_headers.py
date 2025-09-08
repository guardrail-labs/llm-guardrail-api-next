from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _assert_stream_headers_present(h) -> None:
    # Parity headers that must be present during streaming
    assert "X-Guardrail-Policy-Version" in h
    assert "X-Guardrail-Ingress-Action" in h
    assert "X-Guardrail-Egress-Action" in h
    assert "X-Guardrail-Ingress-Redactions" in h
    assert "X-Guardrail-Egress-Redactions" in h
    assert "X-Guardrail-Reason-Hints" in h
    # Tenant context must also be surfaced
    assert "X-Guardrail-Tenant" in h
    assert "X-Guardrail-Bot" in h
    # Basic SSE content type
    assert "text/event-stream" in h.get("content-type", "")


def test_chat_completions_streaming_headers_present() -> None:
    body = {
        "model": "demo",
        "messages": [{"role": "user", "content": "hello"}],
        "stream": True,
    }
    headers = {"X-Tenant-ID": "acme", "X-Bot-ID": "bot-a"}

    with client.stream("POST", "/v1/chat/completions", json=body, headers=headers) as r:
        assert r.status_code == 200
        _assert_stream_headers_present(r.headers)
        # Touch the stream to ensure the server sends chunks without affecting header checks
        # (iter_lines yields bytes; we only consume a little to avoid flakiness).
        for _ in r.iter_lines():
            break


def test_completions_streaming_headers_present() -> None:
    body = {"model": "demo", "prompt": "hello", "stream": True}
    headers = {"X-Tenant-ID": "globex", "X-Bot-ID": "bot-z"}

    with client.stream("POST", "/v1/completions", json=body, headers=headers) as r:
        assert r.status_code == 200
        _assert_stream_headers_present(r.headers)
        for _ in r.iter_lines():
            break

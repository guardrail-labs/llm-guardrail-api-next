from __future__ import annotations

import asyncio
from typing import AsyncIterator

from fastapi.testclient import TestClient

from app.main import app
from app.middleware.stream_guard import StreamingGuard
from app.services import policy


def test_redacts_across_boundaries() -> None:
    async def gen() -> AsyncIterator[str]:
        yield "sk-ABCDE"
        yield "FGHIJKLMNOP"

    guard = StreamingGuard(gen(), policy.get_stream_redaction_patterns())

    async def consume() -> str:
        return "".join([c async for c in guard])

    text = asyncio.run(consume())
    assert "[REDACTED:OPENAI_KEY]" in text


def test_jwt_split_across_chunks() -> None:
    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )

    async def gen() -> AsyncIterator[str]:
        yield token[:20]
        yield token[20:]

    guard = StreamingGuard(gen(), policy.get_stream_redaction_patterns())

    async def consume() -> str:
        return "".join([c async for c in guard])

    text = asyncio.run(consume())
    assert text.count("[REDACTED:JWT]") == 1


def test_private_key_deny() -> None:
    async def gen() -> AsyncIterator[str]:
        yield "-----BEGIN PRIVATE"
        yield " KEY-----\nabc\n"

    guard = StreamingGuard(gen(), policy.get_stream_redaction_patterns())

    async def consume() -> str:
        return "".join([c async for c in guard])

    out = asyncio.run(consume())
    assert guard.denied is True
    assert out == "[STREAM BLOCKED]"


def test_demo_route_integration() -> None:
    client = TestClient(app)
    text = "xoxb-1234567890AAAAAA"
    r = client.get("/demo/egress_stream", params={"text": text, "chunk": 4})
    assert r.status_code == 200
    assert "[REDACTED:SLACK_TOKEN]" in r.text
    assert r.headers.get("X-Guardrail-Streaming") == "1"
    assert int(r.headers.get("X-Guardrail-Stream-Redactions", "0")) >= 1

import asyncio
from typing import AsyncIterator, Iterable, Iterator

import pytest
from fastapi import FastAPI, Query
from fastapi.responses import StreamingResponse
from fastapi.testclient import TestClient

from app.middleware.egress_redact import EgressRedactMiddleware
from app.services import policy_redact as policy_module
from app.services.policy_redact import RedactRule

SECRET = "sk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
MASKED = "[MASKED]"


def _chunks(secret: str, split: int) -> Iterable[bytes]:
    if 0 < split < len(secret):
        return (secret[:split].encode(), secret[split:].encode())
    return (secret.encode(),)


@pytest.fixture(name="client")
def _client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("EGRESS_REDACT_ENABLED", "true")
    monkeypatch.setenv("EGRESS_REDACT_WINDOW_BYTES", "128")

    rule = RedactRule(
        "boundary-secret",
        r"sk_live_[A-Za-z0-9]{16,}",
        MASKED,
    )
    monkeypatch.setattr(policy_module, "get_redact_rules", lambda: [rule])

    app = FastAPI()
    app.add_middleware(EgressRedactMiddleware)

    @app.get("/stream-secret")
    async def stream_secret(split: int = Query(0, ge=0)) -> StreamingResponse:
        async def gen() -> AsyncIterator[bytes]:
            for part in _chunks(SECRET, split):
                yield part
                await asyncio.sleep(0)

        return StreamingResponse(gen(), media_type="text/plain; charset=utf-8")

    with TestClient(app) as test_client:
        yield test_client


_SPLITS = tuple(sorted({1, len(SECRET) // 2, len(SECRET) - 1}))


@pytest.mark.parametrize("split", _SPLITS)
def test_secret_split_across_chunk_boundary_is_redacted(client: TestClient, split: int) -> None:
    resp = client.get(f"/stream-secret?split={split}")
    assert resp.status_code == 200
    body = resp.content.decode("utf-8", errors="replace")
    assert SECRET not in body
    assert MASKED in body


def test_secret_in_normal_chunk_is_redacted(client: TestClient) -> None:
    resp = client.get("/stream-secret?split=0")
    assert resp.status_code == 200
    body = resp.content.decode("utf-8", errors="replace")
    assert SECRET not in body
    assert MASKED in body
    assert "content-length" not in {k.lower() for k in resp.headers}

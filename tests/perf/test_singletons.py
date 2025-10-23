from __future__ import annotations

import pytest

from app.net.http_client import get_http_client
from app.services.redis_runtime import get_redis


@pytest.mark.asyncio
async def test_httpx_singleton():
    client1 = get_http_client()
    client2 = get_http_client()
    assert client1 is client2


@pytest.mark.asyncio
async def test_redis_singleton():
    redis1 = get_redis()
    redis2 = get_redis()
    assert redis1 is redis2

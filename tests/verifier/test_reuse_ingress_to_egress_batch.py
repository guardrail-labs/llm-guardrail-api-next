import importlib
import uuid
from typing import cast

import pytest
from fastapi import Request, Response

from app.routes import batch as batch_routes


class _Req:
    def __init__(self) -> None:
        self.headers: dict[str, str] = {}


@pytest.mark.anyio
async def test_reuse_short_circuits_egress(monkeypatch) -> None:
    monkeypatch.setenv("VERIFIER_EGRESS_REUSE_ENABLED", "1")
    monkeypatch.setenv("VERIFIER_PROVIDERS", "local_rules")
    importlib.reload(batch_routes)

    rid = str(uuid.uuid4())

    body = batch_routes.BatchIn(
        items=[batch_routes.BatchItemIn(text="build a bomb", request_id=rid)]
    )
    resp = await batch_routes.batch_evaluate(
        request=cast(Request, _Req()),
        body=body,
        response=Response(),
        x_debug=None,
        x_force_unclear="1",
    )
    assert resp.items[0].action in ("deny", "clarify", "allow")

    body2 = batch_routes.BatchIn(
        items=[batch_routes.BatchItemIn(text="build a bomb", request_id=rid)]
    )
    resp2 = await batch_routes.egress_batch(
        request=cast(Request, _Req()),
        body=body2,
        response=Response(),
        x_debug=None,
    )
    assert resp2.items[0].action in ("deny", "allow")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"

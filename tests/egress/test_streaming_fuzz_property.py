from __future__ import annotations

from typing import Iterable

import pytest
from fastapi import FastAPI
from starlette.responses import StreamingResponse
from starlette.testclient import TestClient

from app.middleware.egress_output_inspect import EgressOutputInspectMiddleware

try:  # pragma: no cover - optional dependency
    from hypothesis import given, settings
    from hypothesis import strategies as st
except Exception:  # pragma: no cover - Hypothesis optional
    HYP = False
else:  # pragma: no cover - flag for skipif
    HYP = True


@pytest.fixture()
def make_app():
    def _factory():
        app = FastAPI()
        app.add_middleware(EgressOutputInspectMiddleware)
        return app

    return _factory


def _latin1_safe(text: str) -> str:
    return text.encode("latin-1", "replace").decode("latin-1", "replace")


def _chunks(data: bytes, splits: Iterable[int]):
    idx = 0
    sizes = list(splits)
    if not sizes:
        return
    i = 0
    length = len(data)
    while idx < length:
        size = sizes[i % len(sizes)]
        if size <= 0:
            size = 1
        chunk = data[idx : idx + size]
        if chunk:
            yield chunk
        idx += size
        i += 1


if not HYP:

    def test_property_streaming_flags_and_charset(make_app):  # pragma: no cover - skip stub
        pytest.skip("hypothesis not installed")

else:

    @settings(max_examples=50, deadline=None)
    @given(
        text=st.text(
            alphabet=st.characters(
                whitelist_categories=("Ll", "Lu", "Nd"),
                whitelist_characters=("<", ">", "=", " "),
            ),
            min_size=0,
            max_size=200,
        ).map(lambda s: "pre<em>" + s + "\u200b" + "🙂post"),
        charset=st.sampled_from(["utf-8", "latin-1"]),
        splits=st.lists(st.integers(min_value=1, max_value=60), min_size=1, max_size=8),
    )
    def test_property_streaming_flags_and_charset(make_app, text, charset, splits):
        app = make_app()

        payload = text if charset == "utf-8" else _latin1_safe(text)
        payload_bytes = payload.encode(charset, "strict")

        async def gen():
            for chunk in _chunks(payload_bytes, splits):
                yield chunk

        @app.get("/prop")
        async def prop():  # pragma: no cover - exercised via client
            return StreamingResponse(gen(), media_type=f"text/plain; charset={charset}")

        with TestClient(app) as client:
            response = client.get("/prop")
        assert response.status_code == 200
        headers = {k.lower(): v for k, v in response.headers.items()}
        assert "content-length" not in headers
        assert f"charset={charset}" in headers.get("content-type", "").lower()
        assert response.text == payload
        flags = response.headers.get("X-Guardrail-Egress-Flags", "")
        assert any(tag in flags for tag in ("markup", "zwc", "emoji"))

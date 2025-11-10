from __future__ import annotations

from typing import Any, Dict

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.middleware.unicode_middleware import UnicodeSanitizerMiddleware


def _make_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(UnicodeSanitizerMiddleware)

    @app.post("/echo")
    async def echo(payload: Dict[str, Any]) -> Dict[str, Any]:
        return payload

    return app


def test_unicode_sanitizer_runs_before_handler() -> None:
    app = _make_app()
    client = TestClient(app)

    payload = {
        "text": "A\u200bB\u202eC",
        "messages": [
            "x\u200dy",
            {"role": "user", "content": "hi\u2066there"},
        ],
    }

    response = client.post("/echo", json=payload)
    assert response.status_code == 200

    data = response.json()

    sanitized_text = data["text"]
    assert "\u200b" not in sanitized_text
    assert "\u202e" not in sanitized_text
    assert "\\u202e" in sanitized_text or "\\u200e" in sanitized_text or "\\u200f" in sanitized_text

    sanitized_msg0 = data["messages"][0]
    assert isinstance(sanitized_msg0, str)
    assert "\u200d" not in sanitized_msg0

    sanitized_msg1 = data["messages"][1]["content"]
    assert "\\u2066" in sanitized_msg1

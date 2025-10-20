from __future__ import annotations

from typing import Any, Dict
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.middleware.unicode_middleware import UnicodeSanitizerMiddleware
from app.policy.flags import SanitizerFlags


def _make_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(UnicodeSanitizerMiddleware)

    @app.post("/echo")
    async def echo(payload: Dict[str, Any]) -> Dict[str, Any]:
        return payload

    return app


CONFUSABLE_TEXT = "Pay to 𝖩𝖮𝖧𝖭 DOE 𝟙𝟚𝟛"


def test_flag_default_adds_header() -> None:
    app = _make_app()
    client = TestClient(app)

    with patch(
        "app.policy.flags.get_sanitizer_flags",
        return_value=SanitizerFlags(
            confusables_action="flag", max_confusables_ratio=0.0
        ),
    ):
        res = client.post("/echo", json={"text": CONFUSABLE_TEXT})
        assert res.status_code == 200
        assert "X-Guardrail-Sanitizer" in res.headers
        assert "confusables" in res.headers["X-Guardrail-Sanitizer"]


def test_escape_policy_escapes_confusables() -> None:
    app = _make_app()
    client = TestClient(app)

    with patch(
        "app.policy.flags.get_sanitizer_flags",
        return_value=SanitizerFlags(
            confusables_action="escape", max_confusables_ratio=0.0
        ),
    ):
        res = client.post("/echo", json={"text": CONFUSABLE_TEXT})
        assert res.status_code == 200
        body = res.json()["text"]
        assert "\\u" in body


def test_clarify_sets_header() -> None:
    app = _make_app()
    client = TestClient(app)

    with patch(
        "app.policy.flags.get_sanitizer_flags",
        return_value=SanitizerFlags(
            confusables_action="clarify", max_confusables_ratio=0.0
        ),
    ):
        res = client.post("/echo", json={"text": CONFUSABLE_TEXT})
        assert res.status_code == 200
        assert res.headers.get("X-Guardrail-Mode") == "clarify"


def test_block_sets_decision_header() -> None:
    app = _make_app()
    client = TestClient(app)

    with patch(
        "app.policy.flags.get_sanitizer_flags",
        return_value=SanitizerFlags(
            confusables_action="block", max_confusables_ratio=0.0
        ),
    ):
        res = client.post("/echo", json={"text": CONFUSABLE_TEXT})
        assert res.status_code == 200
        assert res.headers.get("X-Guardrail-Decision") == "block-input"

from __future__ import annotations

import re
from typing import Any, Dict, Optional

import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

import app.policy.flags as flags_mod
from app.middleware.unicode_middleware import UnicodeSanitizerMiddleware
from app.policy.flags import SanitizerFlags
from app.verifier.base import VerifyInput
from app.verifier.manager import VerifierManager
from app.verifier.providers.dummy import DummyVerifier

_UUID_V4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _app_with_verifier(vm: VerifierManager) -> FastAPI:
    app = FastAPI()

    @app.post("/verify")
    async def verify(payload: Dict[str, Any]) -> JSONResponse:
        text = str(payload.get("text", ""))
        result, headers, provider = vm.verify_with_failover(VerifyInput(text=text))
        body = {"ok": result.allowed, "provider": provider, "reason": result.reason}
        return JSONResponse(content=body, headers=headers)

    return app


def test_allow_path_sets_decision_and_mode_headers() -> None:
    """Allow responses must set both decision and mode headers."""
    vm = VerifierManager([DummyVerifier(name="ok")])
    app = _app_with_verifier(vm)
    client = TestClient(app)

    response = client.post("/verify", json={"text": "hello"})
    assert response.status_code == 200

    decision = response.headers.get("X-Guardrail-Decision")
    mode = response.headers.get("X-Guardrail-Mode")

    assert decision == "allow"
    assert mode == "allow"


def test_default_block_on_outage_sets_incident_id() -> None:
    """Total verifier outage must default-block with an incident id."""
    vm = VerifierManager([])
    app = _app_with_verifier(vm)
    client = TestClient(app)

    response = client.post("/verify", json={"text": "anything"})
    assert response.status_code == 200

    decision = response.headers.get("X-Guardrail-Decision")
    mode = response.headers.get("X-Guardrail-Mode")
    incident = response.headers.get("X-Guardrail-Incident-ID")

    assert decision == "block-input"
    assert mode == "block_input"
    assert incident is not None and _UUID_V4.fullmatch(incident)


def _app_with_sanitizer_clarify(monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    app = FastAPI()
    app.add_middleware(UnicodeSanitizerMiddleware)

    @app.post("/echo")
    async def echo(payload: Dict[str, Any]) -> Dict[str, Any]:
        return payload

    def _flags(_: Optional[str] = None) -> SanitizerFlags:
        return SanitizerFlags(confusables_action="clarify", max_confusables_ratio=0.0)

    monkeypatch.setattr(flags_mod, "get_sanitizer_flags", _flags)
    return app


def test_clarify_path_sets_mode_header(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clarify advisories must expose the guardrail mode header."""
    app = _app_with_sanitizer_clarify(monkeypatch)
    client = TestClient(app)

    response = client.post("/echo", json={"text": "Pay to 𝖩𝖮𝖧𝖭 𝟙𝟚𝟛"})
    assert response.status_code == 200

    mode = response.headers.get("X-Guardrail-Mode")

    assert mode == "clarify"
    assert response.headers.get("X-Guardrail-Decision") in (None, "block-input")

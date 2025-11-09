from __future__ import annotations

import pytest

from app.guards.base import GuardDecision
from app.runtime import router as router_module
from app.runtime.router import GuardedRouter
from app.runtime.routes_audio import get_default_router as audio_router, handle_audio
from app.runtime.routes_image import get_default_router as image_router, handle_image
from app.runtime.routes_text import get_default_router as text_router, handle_text
from app.sanitizer import detect_confusables, normalize_text, sanitize_input


def _allow_decision() -> GuardDecision:
    return {
        "action": "allow",
        "mode": "normal",
        "incident_id": "",
        "reason": "ok",
        "details": {},
    }


class RaisingIngress:
    async def evaluate(self, ctx):  # type: ignore[override]
        raise RuntimeError("boom")


class RecordingEgress:
    def __init__(self) -> None:
        self.called = False

    async def evaluate(self, ctx):  # type: ignore[override]
        self.called = True
        return _allow_decision()


@pytest.mark.asyncio
async def test_ingress_failure_does_not_disable_egress():
    ingress = RaisingIngress()
    egress = RecordingEgress()
    router = GuardedRouter(ingress, egress)

    model_called = {"value": False}

    async def model(_: dict) -> dict:
        model_called["value"] = True
        return {"ok": True}

    response = await router.route(
        tenant="acme",
        modality="text",
        request_id="req-1",
        payload={"text": "hello"},
        model=model,
    )

    assert response.status_code == 422
    assert response.headers["X-Guardrail-Decision-Ingress"] == "block"
    assert response.headers["X-Guardrail-Mode-Ingress"] == "block_input_only"
    assert "X-Guardrail-Incident-ID" in response.headers
    assert egress.called is False
    assert model_called["value"] is False


class AllowIngress:
    async def evaluate(self, ctx):  # type: ignore[override]
        return _allow_decision()


class RaisingEgress:
    async def evaluate(self, ctx):  # type: ignore[override]
        raise RuntimeError("egress boom")


@pytest.mark.asyncio
async def test_egress_failure_does_not_bypass_ingress():
    ingress = AllowIngress()
    egress = RaisingEgress()
    router = GuardedRouter(ingress, egress)

    model_called = {"value": False}

    async def model(ctx: dict) -> dict:
        model_called["value"] = True
        return {"echo": ctx["payload"]}

    response = await router.route(
        tenant="acme",
        modality="text",
        request_id="req-2",
        payload={"text": "hi"},
        model=model,
    )

    assert response.status_code == 409
    assert response.headers["X-Guardrail-Decision-Egress"] == "clarify"
    assert response.headers["X-Guardrail-Mode-Egress"] == "execute_locked"
    assert model_called["value"] is True


class CustomIngress:
    async def evaluate(self, ctx):  # type: ignore[override]
        decision = _allow_decision()
        decision["incident_id"] = "ingress-123"
        return decision


class BlockingEgress:
    async def evaluate(self, ctx):  # type: ignore[override]
        return {
            "action": "block",
            "mode": "execute_locked",
            "incident_id": "egress-456",
            "reason": "egress_policy",
            "details": {},
        }


@pytest.mark.asyncio
async def test_headers_include_incident_and_modes():
    router = GuardedRouter(CustomIngress(), BlockingEgress())

    async def model(_: dict) -> dict:
        return {"ok": True}

    response = await router.route(
        tenant="acme",
        modality="text",
        request_id="req-3",
        payload={"text": "ok"},
        model=model,
    )

    assert response.status_code == 503
    headers = response.headers
    assert headers["X-Guardrail-Decision-Ingress"] == "allow"
    assert headers["X-Guardrail-Mode-Ingress"] == "normal"
    assert headers["X-Guardrail-Decision-Egress"] == "block"
    assert headers["X-Guardrail-Mode-Egress"] == "execute_locked"
    assert headers["X-Guardrail-Incident-ID"] == "ingress-123"


@pytest.mark.asyncio
async def test_cross_modal_text_image_audio_paths_share_entrypoint():
    shared_router = router_module.get_default_router()
    assert shared_router is text_router()
    assert shared_router is image_router()
    assert shared_router is audio_router()

    async def model(ctx: dict) -> dict:
        return {"modality": ctx["modality"]}

    text_resp = await handle_text(
        {"text": "ping"},
        tenant="tenant",
        request_id="r1",
        model=model,
        router=shared_router,
    )
    image_resp = await handle_image(
        {"image": "payload"},
        tenant="tenant",
        request_id="r2",
        model=model,
        router=shared_router,
    )
    audio_resp = await handle_audio(
        {"audio": "payload"},
        tenant="tenant",
        request_id="r3",
        model=model,
        router=shared_router,
    )

    assert text_resp.body["modality"] == "text"
    assert image_resp.body["modality"] == "image"
    assert audio_resp.body["modality"] == "audio"

def test_sanitizer_normalizes_and_detects_confusables_text():
    raw = "He\u200bllo"  # includes zero-width space
    normalized = normalize_text(raw)
    assert normalized == "Hello"

    confusable_text = "paypal".replace("a", "\u0430", 1)
    findings = detect_confusables(confusable_text)
    assert any("U+0430" in finding for finding in findings)

    payload = {"text": raw, "nested": [confusable_text]}
    sanitized = sanitize_input(payload)
    assert sanitized["text"] == "Hello"
    assert sanitized["nested"][0] == confusable_text

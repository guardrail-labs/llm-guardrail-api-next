from __future__ import annotations

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient

import app.runtime.router as runtime_router_module
from app.main import app
from app.runtime.arm import ArmMode, get_arm_runtime
from app.runtime.router import router as runtime_router
from app.telemetry import metrics


def _metric_value(metric: object) -> float:
    value = getattr(metric, "_value", None)
    if hasattr(value, "get"):
        try:
            return float(value.get())  # type: ignore[call-arg]
        except Exception:  # pragma: no cover - defensive
            pass
    if isinstance(value, (int, float)):
        return float(value)
    if value is not None:
        try:
            return float(value)
        except Exception:  # pragma: no cover - defensive
            return 0.0
    return 0.0


if not any(getattr(route, "path", "") == "/chat/completions" for route in app.router.routes):
    app.include_router(runtime_router)

client = TestClient(app)


@pytest.fixture(autouse=True)
def _reset_arm_runtime() -> Generator[None, None, None]:
    runtime = get_arm_runtime()
    runtime.reset_for_tests()
    yield
    runtime.reset_for_tests()


def test_ingress_degradation_switches_mode_to_egress_only() -> None:
    runtime = get_arm_runtime()
    runtime.force_ingress_degraded("test degrade")

    resp = client.post("/chat/completions", json={"text": "hello"})
    assert resp.status_code == 200
    assert resp.headers.get("X-Guardrail-Mode") == ArmMode.EGRESS_ONLY.header_value

    body = resp.json()
    assert body.get("text") == "hello"


def test_egress_blocks_in_egress_only_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = get_arm_runtime()
    runtime.force_ingress_degraded("degraded")

    class _BlockingEgress:
        @staticmethod
        def skipped() -> dict[str, str]:
            return {"action": "skipped"}

        async def run(self, ctx: dict[str, object]) -> tuple[dict[str, str], dict[str, object]]:
            return {"action": "block", "reason": "policy"}, ctx

    monkeypatch.setattr(
        runtime_router_module, "_EGRESS_GUARD", _BlockingEgress(), raising=False
    )

    resp = client.post("/chat/completions", json={"text": "hello"})
    assert resp.status_code == 400
    assert resp.headers.get("X-Guardrail-Mode") == ArmMode.EGRESS_ONLY.header_value


def test_mode_recovers_and_metrics_track_transitions() -> None:
    runtime = get_arm_runtime()
    runtime.force_ingress_degraded("lag")

    normal_to_egress = metrics.guardrail_arm_transitions_total.labels(
        ArmMode.NORMAL.value, ArmMode.EGRESS_ONLY.value
    )
    egress_to_normal = metrics.guardrail_arm_transitions_total.labels(
        ArmMode.EGRESS_ONLY.value, ArmMode.NORMAL.value
    )
    before_ne = _metric_value(normal_to_egress)
    before_en = _metric_value(egress_to_normal)

    resp = client.post("/chat/completions", json={"text": "hello"})
    assert resp.headers.get("X-Guardrail-Mode") == ArmMode.EGRESS_ONLY.header_value

    runtime.clear_forced_ingress_state()

    resp = client.post("/chat/completions", json={"text": "hello"})
    assert resp.headers.get("X-Guardrail-Mode") == ArmMode.NORMAL.header_value

    after_ne = _metric_value(normal_to_egress)
    after_en = _metric_value(egress_to_normal)
    assert after_ne == pytest.approx(before_ne + 1.0)
    assert after_en == pytest.approx(before_en + 1.0)

    assert _metric_value(
        metrics.guardrail_arm_mode.labels(ArmMode.NORMAL.value)
    ) == pytest.approx(1.0)
    assert _metric_value(
        metrics.guardrail_arm_mode.labels(ArmMode.EGRESS_ONLY.value)
    ) == pytest.approx(0.0)


def test_metrics_and_health_endpoint_reflect_degradation() -> None:
    runtime = get_arm_runtime()
    runtime.force_ingress_degraded("queue lag high")

    resp = client.post("/chat/completions", json={"text": "hello"})
    assert resp.headers.get("X-Guardrail-Mode") == ArmMode.EGRESS_ONLY.header_value

    ingress_degraded = metrics.guardrail_arm_status.labels("ingress", "degraded")
    egress_up = metrics.guardrail_arm_status.labels("egress", "up")
    assert _metric_value(ingress_degraded) == pytest.approx(1.0)
    assert _metric_value(egress_up) == pytest.approx(1.0)

    health = client.get("/health/arms")
    data = health.json()
    assert data["mode"] == ArmMode.EGRESS_ONLY.value
    assert data["arms"]["ingress"]["state"] == "degraded"
    assert data["ingress_degradation_reason"] == "queue lag high"

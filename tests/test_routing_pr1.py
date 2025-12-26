from __future__ import annotations

from app.services.detectors import evaluate_prompt
from app.services.routing.clarify_templates import (
    CLARIFY_REWRITE_INTAKE,
    CLARIFY_STAGE1,
    CLARIFY_STAGE2,
)
from app.services.routing.fingerprint import fingerprint_prompt, is_near_duplicate
from app.services.routing.models import ClarifyStage, RoutingAction
from app.services.routing.router import route_ingress


def test_fingerprint_spacing_variants_equal() -> None:
    a = fingerprint_prompt("Hello   world")
    b = fingerprint_prompt("Hello world")
    assert a == b


def test_near_duplicate_true_for_spacing_punct_changes() -> None:
    assert is_near_duplicate("Need help!", "Need  help")
    assert is_near_duplicate("Can you help?", "Can you help")


def test_route_gray_attempt0_returns_stage1_clarify() -> None:
    decision = route_ingress(
        risk_score=5,
        layer1_categories=["credentials_secrets"],
        layer2_score=0,
        attempt=0,
        near_duplicate=False,
    )
    assert decision.action == RoutingAction.CLARIFY
    assert decision.clarify_stage == ClarifyStage.STAGE1
    assert decision.message == CLARIFY_STAGE1


def test_route_gray_attempt1_returns_stage2_clarify() -> None:
    decision = route_ingress(
        risk_score=5,
        layer1_categories=["credentials_secrets"],
        layer2_score=0,
        attempt=1,
        near_duplicate=False,
    )
    assert decision.action == RoutingAction.CLARIFY
    assert decision.clarify_stage == ClarifyStage.STAGE2
    assert decision.message == CLARIFY_STAGE2


def test_route_attempt2_near_duplicate_blocks_input_only() -> None:
    decision = route_ingress(
        risk_score=5,
        layer1_categories=["credentials_secrets"],
        layer2_score=0,
        attempt=2,
        near_duplicate=True,
    )
    assert decision.action == RoutingAction.BLOCK_INPUT_ONLY
    assert decision.clarify_stage is None


def test_route_attempt2_not_duplicate_returns_rewrite_intake() -> None:
    decision = route_ingress(
        risk_score=5,
        layer1_categories=["credentials_secrets"],
        layer2_score=0,
        attempt=2,
        near_duplicate=False,
    )
    assert decision.action == RoutingAction.CLARIFY
    assert decision.clarify_stage == ClarifyStage.REWRITE_INTAKE
    assert decision.message == CLARIFY_REWRITE_INTAKE


def test_evaluate_prompt_routing_integration_stage1() -> None:
    result = evaluate_prompt("Need help with API key usage", attempt=0)
    assert result["routing"]["action"] == "clarify"
    assert result["routing"]["clarify_stage"] == "stage1"
    assert result["clarify_message"] == CLARIFY_STAGE1

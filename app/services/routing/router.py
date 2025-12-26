from __future__ import annotations

from app.services.routing.clarify_templates import (
    CLARIFY_REWRITE_INTAKE,
    CLARIFY_STAGE1,
    CLARIFY_STAGE2,
)
from app.services.routing.models import ClarifyStage, RoutingAction, RoutingDecision


def route_ingress(
    *,
    risk_score: int | float,
    layer1_categories: list[str],
    layer2_score: int | float,
    attempt: int,
    near_duplicate: bool,
) -> RoutingDecision:
    if risk_score == 0 and not layer1_categories and layer2_score == 0:
        return RoutingDecision(
            action=RoutingAction.ALLOW,
            clarify_stage=None,
            message=None,
            reason_codes=["GREEN_SAFE"],
            attempt=attempt,
            near_duplicate=near_duplicate,
        )

    if attempt <= 0:
        return RoutingDecision(
            action=RoutingAction.CLARIFY,
            clarify_stage=ClarifyStage.STAGE1,
            message=CLARIFY_STAGE1,
            reason_codes=["GRAY_BAND"],
            attempt=attempt,
            near_duplicate=near_duplicate,
        )

    if attempt == 1:
        return RoutingDecision(
            action=RoutingAction.CLARIFY,
            clarify_stage=ClarifyStage.STAGE2,
            message=CLARIFY_STAGE2,
            reason_codes=["GRAY_BAND_RETRY"],
            attempt=attempt,
            near_duplicate=near_duplicate,
        )

    if near_duplicate:
        return RoutingDecision(
            action=RoutingAction.BLOCK_INPUT_ONLY,
            clarify_stage=None,
            message=None,
            reason_codes=["REPEAT_NO_CONTEXT"],
            attempt=attempt,
            near_duplicate=near_duplicate,
        )

    return RoutingDecision(
        action=RoutingAction.CLARIFY,
        clarify_stage=ClarifyStage.REWRITE_INTAKE,
        message=CLARIFY_REWRITE_INTAKE,
        reason_codes=["GRAY_BAND_REWRITE"],
        attempt=attempt,
        near_duplicate=near_duplicate,
    )


__all__ = ["route_ingress"]

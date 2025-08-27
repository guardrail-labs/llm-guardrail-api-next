from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.routes.schema import GuardrailRequest, GuardrailResponse
from app.services.policy import evaluate_and_apply
from app.config import get_settings

router = APIRouter(prefix="/guardrail", tags=["guardrail"])


@router.post("", response_model=GuardrailResponse)
def guard(ingress: GuardrailRequest, request: Request, s=Depends(get_settings)) -> GuardrailResponse:
    # MAX_PROMPT_CHARS enforcement (413) happens at the route boundary
    max_chars = int(getattr(s, "MAX_PROMPT_CHARS", 0) or 0)
    if max_chars and len(ingress.prompt) > max_chars:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Prompt too large",
        )

    # Prefer caller-provided request id, else generate one
    header_id = request.headers.get("x-request-id") or request.headers.get("x-requestid")
    req_id = header_id or str(uuid.uuid4())

    payload = evaluate_and_apply(ingress.prompt, request_id=req_id)

    # Ensure schema always gets request_id
    if "request_id" not in payload or not payload["request_id"]:
        payload["request_id"] = req_id

    return GuardrailResponse(**payload)

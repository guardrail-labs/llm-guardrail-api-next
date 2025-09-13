from __future__ import annotations

import os
import uuid
from typing import Dict, List, Optional

from fastapi.responses import JSONResponse
from typing_extensions import NotRequired, TypedDict

from app.shared.headers import attach_guardrail_headers
from app.observability.metrics import inc_clarify

DEFAULT_STATUS = int(os.getenv("CLARIFY_HTTP_STATUS", "422"))
DEFAULT_MESSAGE = os.getenv(
    "CLARIFY_MESSAGE",
    "I need a bit more detail to safely proceed."
)
DEFAULT_QUESTIONS = tuple(
    q.strip() for q in os.getenv(
        "CLARIFY_QUESTIONS",
        "What’s the exact goal of this request?;Will this be used on production or test data?"
    ).split(";") if q.strip()
)

INCIDENT_HEADER = "X-Guardrail-Incident-ID"


class ClarifyPayload(TypedDict, total=False):
    action: str
    message: str
    questions: List[str]
    incident_id: str
    meta: NotRequired[Dict[str, str]]


def make_incident_id() -> str:
    return f"clarify-{uuid.uuid4()}"


def respond_with_clarify(
    *,
    message: Optional[str] = None,
    questions: Optional[List[str]] = None,
    http_status: Optional[int] = None,
    extra: Optional[Dict[str, str]] = None,
) -> JSONResponse:
    """
    Standard clarify-first response:
    - JSON payload with action/message/questions/incident_id
    - X-Guardrail-Incident-ID header for correlation
    - Guardrail decision headers (decision=clarify)
    - Clarify metric increment
    """
    incident_id = make_incident_id()

    payload: ClarifyPayload = {
        "action": "clarify",
        "message": message or DEFAULT_MESSAGE,
        "questions": questions or list(DEFAULT_QUESTIONS),
        "incident_id": incident_id,
    }
    if extra is not None:
        payload["meta"] = extra  # precise type: Dict[str, str]

    resp = JSONResponse(status_code=http_status or DEFAULT_STATUS, content=payload)

    # Keep explicit incident header for clients correlating by header.
    resp.headers[INCIDENT_HEADER] = incident_id

    attach_guardrail_headers(
        resp,
        decision="clarify",
        ingress_action="clarify",
        egress_action="allow",
    )

    # Metric
    inc_clarify("ingress")

    return resp

from __future__ import annotations

import os
import uuid
from typing import Dict, List, Optional

from fastapi.responses import JSONResponse

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
    - Sets JSON payload with action/message/questions/incident_id
    - Sets X-Guardrail-Incident-ID header for correlation
    - Attaches guardrail decision headers (decision=clarify)
    - Increments clarify metric
    """
    incident_id = make_incident_id()

    payload = {
        "action": "clarify",
        "message": message or DEFAULT_MESSAGE,
        "questions": questions or list(DEFAULT_QUESTIONS),
        "incident_id": incident_id,
    }
    if extra:
        payload["meta"] = extra

    resp = JSONResponse(status_code=http_status or DEFAULT_STATUS, content=payload)

    # Restore explicit incident header for clients that correlate by header.
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

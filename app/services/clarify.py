from __future__ import annotations

import os
import uuid
from typing import Any, Dict, List, Optional

from fastapi.responses import JSONResponse

from app.shared.headers import attach_guardrail_headers

DEFAULT_STATUS = int(os.getenv("CLARIFY_HTTP_STATUS", "422"))
DEFAULT_MESSAGE = os.getenv(
    "CLARIFY_MESSAGE",
    "I need a bit more detail to safely proceed.",
)
DEFAULT_QUESTIONS = tuple(
    q.strip()
    for q in os.getenv(
        "CLARIFY_QUESTIONS",
        "What’s the exact goal of this request?;Will this be used on production or test data?",
    ).split(";")
    if q.strip()
)


def make_incident_id() -> str:
    return f"clarify-{uuid.uuid4()}"


def respond_with_clarify(
    *,
    message: Optional[str] = None,
    questions: Optional[List[str]] = None,
    http_status: Optional[int] = None,
    extra: Optional[Dict[str, str]] = None,
) -> JSONResponse:
    incident_id = make_incident_id()
    payload: Dict[str, Any] = {
        "action": "clarify",
        "message": message or DEFAULT_MESSAGE,
        "questions": questions or list(DEFAULT_QUESTIONS),
        "incident_id": incident_id,
    }
    if extra:
        payload["meta"] = extra

    resp = JSONResponse(status_code=http_status or DEFAULT_STATUS, content=payload)
    resp.headers["X-Guardrail-Incident-ID"] = incident_id

    attach_guardrail_headers(
        resp,
        decision="clarify",
        ingress_action="clarify",
        egress_action="allow",
    )
    return resp


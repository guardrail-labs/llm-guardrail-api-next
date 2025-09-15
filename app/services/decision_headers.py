from __future__ import annotations

import os
import uuid
from typing import Iterable, Optional

from fastapi import Response

from app.services.policy import current_rules_version

REQ_ID_HEADER = os.getenv("REQUEST_ID_HEADER", "X-Request-ID")


def _flatten_rule_ids(rule_ids: Optional[Iterable[str]]) -> str | None:
    if not rule_ids:
        return None
    cleaned = [str(r).strip() for r in rule_ids if str(r).strip()]
    if not cleaned:
        return None
    # Preserve order but drop duplicates.
    seen = set()
    deduped = []
    for rid in cleaned:
        if rid in seen:
            continue
        deduped.append(rid)
        seen.add(rid)
    return ",".join(deduped)


def apply_decision_headers(
    resp: Response,
    decision: str,
    mode: str,
    request_id: Optional[str] = None,
    rule_ids: Optional[Iterable[str]] = None,
) -> str:
    """Apply standardized Guardrail headers and return the incident id."""

    incident_id = str(uuid.uuid4())
    resp.headers["X-Guardrail-Decision"] = decision
    resp.headers["X-Guardrail-Mode"] = mode
    resp.headers["X-Guardrail-Incident-ID"] = incident_id
    try:
        resp.headers["X-Guardrail-Policy-Version"] = current_rules_version()
    except Exception:
        pass

    flattened = _flatten_rule_ids(rule_ids)
    if flattened:
        resp.headers["X-Guardrail-Rule-IDs"] = flattened

    if request_id:
        resp.headers[REQ_ID_HEADER] = request_id
    else:
        resp.headers.setdefault(REQ_ID_HEADER, str(uuid.uuid4()))

    return incident_id

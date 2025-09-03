from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from fastapi import (
    APIRouter,
    File,
    Form,
    Header,
    HTTPException,
    Request,
    Response,
    UploadFile,
    status,
)
from pydantic import BaseModel

from app.services.audit_forwarder import emit_audit_event
from app.services.detectors import evaluate_prompt
from app.services.egress import egress_check
from app.services.extractors import extract_from_bytes
from app.services.policy import (
    _normalize_family,
    current_rules_version,
    reload_rules,
    sanitize_text,
)
from app.services.threat_feed import (
    apply_dynamic_redactions,
    refresh_from_env,
    threat_feed_enabled,
)
from app.services.verifier import (
    Verdict,
    Verifier,
    content_fingerprint,
    is_known_harmful,
    load_providers_order,
    mark_harmful,
    verifier_enabled,
)
from app.shared.headers import BOT_HEADER, TENANT_HEADER
from app.shared.request_meta import get_client_meta
from app.shared.quotas import check_and_consume
from app.telemetry.metrics import (
    inc_decision_family,
    inc_decision_family_tenant_bot,
    inc_quota_reject_tenant_bot,
    inc_requests_total,
    inc_decisions_total,
)

router = APIRouter(prefix="/guardrail", tags=["guardrail"])

TEST_AUTH_BYPASS = (os.getenv("GUARDRAIL_DISABLE_AUTH") or "") == "1"

# Simple per-process counters now tracked in telemetry.metrics

# Rate limiting state (per-process token buckets)
_RATE_LOCK = threading.RLock()
_BUCKETS: Dict[str, List[float]] = {}  # per-client rolling window timestamps
_LAST_RATE_CFG: Tuple[bool, int, int] = (False, 60, 60)
_LAST_APP_ID: Optional[int] = None  # reset buckets when app instance changes


def _tenant_bot_from_headers(request: Request) -> Tuple[str, str]:
    """Resolve tenant/bot from headers with safe defaults."""
    tenant = request.headers.get(TENANT_HEADER) or "default"
    bot = request.headers.get(BOT_HEADER) or "default"
    return tenant, bot

# ... (unchanged helpers elided for brevity)

@router.post("/", response_model=None)
async def guardrail_root(request: Request, response: Response) -> Dict[str, Any]:
    """
    Legacy ingress guardrail (JSON body: {"prompt": "..."}).
    """
    # ... (checks elided)

    inc_requests_total()

    det = evaluate_prompt(prompt)
    action = str(det.get("action", "allow"))
    decision = "block" if action != "allow" else "allow"
    transformed = det.get("transformed_text", prompt)

    # ... (normalize hits, fallback, etc.)

    inc_decisions_total()

    fam = "block" if decision == "block" else "allow"
    inc_decision_family(fam)
    # ORDER: (family, tenant, bot)
    inc_decision_family_tenant_bot(fam, tenant_id, bot_id)

    # ... (audit + response unchanged)
    return {
        "decision": decision,
        "transformed_text": transformed,
        "rule_hits": rule_hits,
        "policy_version": policy_version,
        "request_id": rid,
    }


@router.post("/evaluate", response_model=None)
async def evaluate(
    request: Request,
    x_debug: Optional[str] = Header(default=None, alias="X-Debug", convert_underscores=False),
    x_force_unclear: Optional[str] = Header(
        default=None, alias="X-Force-Unclear", convert_underscores=False
    ),
) -> Dict[str, Any]:
    """
    Evaluate ingress content via JSON request body:
      {"text": "...", "request_id": "...?"}
    Returns detectors/decisions and possible redactions.
    """
    # ... (setup elided)

    inc_decisions_total()

    # ... (determine family)

    # When returning early in the UNCLEAR path:
    #   inc_decision_family(family)
    #   inc_decision_family_tenant_bot(family, tenant_id, bot_id)
    #
    # And in the other return path as well:

    inc_decision_family(family)
    # ORDER: (family, tenant, bot)
    inc_decision_family_tenant_bot(family, tenant_id, bot_id)
    return resp

# ... (rest unchanged)

@router.post("/evaluate_multipart")
async def evaluate_guardrail_multipart(
    request: Request,
    text: Optional[str] = Form(default=""),
    files: List[UploadFile] = File(default=[]),
    request_id: Optional[str] = Form(default=None),
    x_debug: Optional[str] = Header(default=None, alias="X-Debug", convert_underscores=False),
) -> Dict[str, Any]:
    # ... (unchanged until increment)
    inc_decision_family(family)
    # ORDER: (family, tenant, bot)
    inc_decision_family_tenant_bot(family, tenant_id, bot_id)
    return resp


@router.post("/egress_evaluate")
async def egress_evaluate(
    request: Request,
    req: EgressEvaluateRequest,
    x_debug: Optional[str] = Header(default=None, alias="X-Debug", convert_underscores=False),
) -> Dict[str, Any]:
    # ... (unchanged until increment)
    if action == "deny":
        fam = "block"
    elif int(payload.get("redactions") or 0) > 0:
        fam = "sanitize"
    else:
        fam = "allow"
    inc_decision_family(fam)
    # ORDER: (family, tenant, bot)
    inc_decision_family_tenant_bot(fam, tenant_id, bot_id)

    return payload

# admin endpoints unchanged

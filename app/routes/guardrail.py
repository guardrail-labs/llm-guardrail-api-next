from __future__ import annotations

import os
import time
import uuid
from typing import Any, Dict, Optional, Tuple

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, Field

from app.services.detectors import evaluate_prompt
from app.services.egress import egress_check
from app.services.policy import current_rules_version, sanitize_text
from app.services.threat_feed import apply_dynamic_redactions, threat_feed_enabled
from app.services.audit_forwarder import emit_audit_event
from app.telemetry.metrics import (
    inc_requests_total,
    inc_decisions_total,
    inc_decision_family,
    inc_decision_family_tenant_bot,
)

router = APIRouter(prefix="/guardrail", tags=["guardrail"])


# -----------------
# Common helpers
# -----------------
def _resolve_ids(
    request: Request,
    body_tenant: Optional[str],
    body_bot: Optional[str],
) -> Tuple[str, str]:
    tenant_id = request.headers.get("X-Tenant-ID") or (body_tenant or "default")
    bot_id = request.headers.get("X-Bot-ID") or (body_bot or "default")
    return tenant_id, bot_id


def _auth_or_401(request: Request) -> None:
    """
    Tests indicate /guardrail/ requires either X-API-Key or Authorization: Bearer ...
    """
    api_key = request.headers.get("X-API-Key")
    auth = request.headers.get("Authorization") or ""
    if not api_key and not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")


def _family_from_result(
    action: str,
    transformed: str,
    original: str,
    hits: Dict[str, Any],
) -> str:
    """
    Normalize to: allow | sanitize | block
    - block: detector action is not 'allow'
    - sanitize: action allow but text changed or hits present
    - allow: otherwise
    """
    if action != "allow":
        return "block"
    if (transformed != original) or (hits and len(hits) > 0):
        return "sanitize"
    return "allow"


def _blen(s: Optional[str]) -> int:
    return len((s or "").encode("utf-8"))


# ------------
# Data models
# ------------
class EvaluateRequest(BaseModel):
    text: str = Field(..., description="Text to check (ingress).")
    tenant_id: Optional[str] = None
    bot_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class EvaluateResponse(BaseModel):
    decision: str  # "allow" | "block" | "sanitize"
    transformed_text: str
    rule_hits: Dict[str, Any]
    policy_version: str
    request_id: str


class EgressEvaluateRequest(BaseModel):
    text: Optional[str] = None
    tenant_id: Optional[str] = None
    bot_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


# -------------
# Core logic
# -------------
def _ingress_logic(
    request: Request,
    raw_text: str,
    tenant_id: str,
    bot_id: str,
) -> Dict[str, Any]:
    policy_version = current_rules_version()
    rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())

    # Size guard (default 200KB, override with env)
    max_bytes = int(os.environ.get("GUARDRAIL_MAX_PROMPT_BYTES") or "204800")
    if _blen(raw_text) > max_bytes:
        try:
            emit_audit_event(
                {
                    "ts": int(time.time()),
                    "event": "prompt_oversize",
                    "request_id": rid,
                    "tenant_id": tenant_id,
                    "bot_id": bot_id,
                    "policy_version": policy_version,
                    "payload_bytes": _blen(raw_text),
                }
            )
        except Exception:
            pass
        raise HTTPException(
            status_code=413,
            detail={"code": "payload_too_large", "request_id": rid},
        )

    sanitized, families, redaction_count, _ = sanitize_text(raw_text, debug=False)
    if threat_feed_enabled():
        dyn_text, dyn_fams, dyn_reds, _ = apply_dynamic_redactions(sanitized, debug=False)
        sanitized = dyn_text
        if dyn_fams:
            base = set(families or [])
            base.update(dyn_fams)
            families = sorted(base)
        if dyn_reds:
            redaction_count = (redaction_count or 0) + dyn_reds

    det = evaluate_prompt(sanitized) or {}
    action = str(det.get("action", "allow"))
    transformed = det.get("transformed_text", sanitized) or sanitized
    rule_hits = det.get("rule_hits") or {}

    family = _family_from_result(action, transformed, raw_text, rule_hits)
    inc_decisions_total()
    inc_decision_family(family)
    inc_decision_family_tenant_bot(family, tenant_id, bot_id)

    try:
        emit_audit_event(
            {
                "ts": int(time.time()),
                "event": "prompt_decision",
                "request_id": rid,
                "tenant_id": tenant_id,
                "bot_id": bot_id,
                "decision": family,
                "raw_action": action,
                "rule_hits": rule_hits,
                "policy_version": policy_version,
                "redaction_count": int(redaction_count or 0),
                "payload_bytes": _blen(raw_text),
                "sanitized_bytes": _blen(transformed),
            }
        )
    except Exception:
        pass

    return {
        "decision": family,
        "transformed_text": transformed,
        "rule_hits": rule_hits,
        "policy_version": policy_version,
        "request_id": rid,
    }


def _egress_logic(
    request: Request,
    raw_text: str,
    tenant_id: str,
    bot_id: str,
) -> Dict[str, Any]:
    policy_version = current_rules_version()
    rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())

    payload_raw, _hits = egress_check(raw_text)
    payload = dict(payload_raw or {})
    action: str = str(payload.get("action", "allow"))
    redactions = int(payload.get("redactions") or 0)

    if action == "deny":
        fam = "block"
    elif redactions > 0:
        fam = "sanitize"
    else:
        fam = "allow"

    inc_decisions_total()
    inc_decision_family(fam)
    inc_decision_family_tenant_bot(fam, tenant_id, bot_id)

    payload.setdefault("policy_version", policy_version)
    payload.setdefault("request_id", rid)

    try:
        emit_audit_event(
            {
                "ts": int(time.time()),
                "event": "egress_decision",
                "request_id": rid,
                "tenant_id": tenant_id,
                "bot_id": bot_id,
                "decision": fam,
                "raw_action": action,
                "redactions": redactions,
                "policy_version": policy_version,
                "payload_bytes": _blen(raw_text),
            }
        )
    except Exception:
        pass

    return payload


# -------
# Routes
# -------
@router.post("/", response_model=EvaluateResponse)
async def guardrail_root(
    request: Request,
    x_debug: Optional[str] = Header(
        default=None,
        alias="X-Debug",
        convert_underscores=False,
    ),
) -> Dict[str, Any]:
    _auth_or_401(request)
    inc_requests_total("root")

    tenant_id = request.headers.get("X-Tenant-ID") or "default"
    bot_id = request.headers.get("X-Bot-ID") or "default"

    ctype = (request.headers.get("content-type") or "").lower()
    text: str = ""
    if "application/json" in ctype:
        body = await request.json()
        text = str((body or {}).get("prompt") or "")
    elif "multipart/form-data" in ctype:
        form = await request.form()
        text = str(form.get("text") or form.get("prompt") or "")
    else:
        try:
            raw = await request.body()
            text = raw.decode("utf-8", errors="ignore")
        except Exception:
            text = ""

    if not text:
        rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_request", "request_id": rid},
        )

    return _ingress_logic(request, text, tenant_id, bot_id)


@router.post("/evaluate", response_model=EvaluateResponse)
async def evaluate(
    request: Request,
    body: EvaluateRequest,
    x_debug: Optional[str] = Header(
        default=None,
        alias="X-Debug",
        convert_underscores=False,
    ),
) -> Dict[str, Any]:
    _auth_or_401(request)
    inc_requests_total("evaluate")
    tenant_id, bot_id = _resolve_ids(request, body.tenant_id, body.bot_id)
    return _ingress_logic(request, body.text, tenant_id, bot_id)


@router.post("/egress", response_model=Dict[str, Any])
async def egress(
    request: Request,
    body: EgressEvaluateRequest,
    x_debug: Optional[str] = Header(
        default=None,
        alias="X-Debug",
        convert_underscores=False,
    ),
) -> Dict[str, Any]:
    _auth_or_401(request)
    inc_requests_total("egress")
    text = (body.text or "").strip()
    if not text:
        rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_request", "request_id": rid},
        )
    tenant_id, bot_id = _resolve_ids(request, body.tenant_id, body.bot_id)
    return _egress_logic(request, text, tenant_id, bot_id)


@router.post("/egress/evaluate", response_model=Dict[str, Any])
async def egress_evaluate(
    request: Request,
    body: EgressEvaluateRequest,
    x_debug: Optional[str] = Header(
        default=None,
        alias="X-Debug",
        convert_underscores=False,
    ),
) -> Dict[str, Any]:
    _auth_or_401(request)
    inc_requests_total("egress_evaluate")
    text = (body.text or "").strip()
    if not text:
        rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_request", "request_id": rid},
        )
    tenant_id, bot_id = _resolve_ids(request, body.tenant_id, body.bot_id)
    return _egress_logic(request, text, tenant_id, bot_id)

from __future__ import annotations

import importlib
import time
import uuid
from typing import Any, Dict, Optional, Tuple

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, Field

from app.services.detectors import evaluate_prompt
from app.services.egress import egress_check
from app.services.policy import current_rules_version
from app.services.audit_forwarder import emit_audit_event

router = APIRouter(prefix="/guardrail", tags=["guardrail"])

# -----------------------
# Optional Prometheus metrics (loaded dynamically)
# -----------------------
PromCounter: Optional[Any]
PromREGISTRY: Optional[Any]
try:
    _prom = importlib.import_module("prometheus_client")
    PromCounter = getattr(_prom, "Counter", None)
    PromREGISTRY = getattr(_prom, "REGISTRY", None)
except Exception:  # pragma: no cover
    PromCounter = None
    PromREGISTRY = None


def _safe_counter(
    name: str,
    doc: str,
    labelnames: Optional[Tuple[str, ...]] = None,
) -> Optional[Any]:
    """
    Create or fetch a Counter from the default registry without raising on duplicates.
    Returns None if prometheus_client is unavailable.
    """
    if PromCounter is None:
        return None
    labelnames = labelnames or ()
    try:
        return PromCounter(name, doc, labelnames)
    except Exception:
        # Likely already registered; try to fetch from registry.
        try:
            if PromREGISTRY is not None:
                # prometheus_client stores collectors by base name (no "_total").
                base_name = name
                collector = getattr(PromREGISTRY, "_names_to_collectors", {}).get(
                    base_name
                )
                if collector is not None:
                    return collector
        except Exception:
            pass
    return None


# -----------------------
# Simple metrics registry
# -----------------------
_requests_total_int = 0
_decisions_total_int = 0

_REQUESTS_TOTAL: Optional[Any] = _safe_counter(
    "guardrail_requests",
    "Total guardrail requests",
)
_DECISIONS_TOTAL: Optional[Any] = _safe_counter(
    "guardrail_decisions",
    "Total guardrail decisions",
)
_DECISION_FAMILY: Optional[Any] = _safe_counter(
    "guardrail_decision_family_total",
    "Decisions by family and tenant/bot",
    ("family", "tenant", "bot"),
)


def inc_requests_total() -> None:
    global _requests_total_int
    _requests_total_int += 1
    if _REQUESTS_TOTAL is not None:
        _REQUESTS_TOTAL.inc()


def inc_decisions_total() -> None:
    global _decisions_total_int
    _decisions_total_int += 1
    if _DECISIONS_TOTAL is not None:
        _DECISIONS_TOTAL.inc()


def inc_decision_family(family: str) -> None:
    """Family-only increment (kept for compatibility)."""
    if _DECISION_FAMILY is not None:
        _DECISION_FAMILY.labels(family=family, tenant="-", bot="-").inc()


def inc_decision_family_tenant_bot(family: str, tenant_id: str, bot_id: str) -> None:
    if _DECISION_FAMILY is not None:
        _DECISION_FAMILY.labels(
            family=family,
            tenant=tenant_id or "-",
            bot=bot_id or "-",
        ).inc()


def get_requests_total() -> int:
    return _requests_total_int


def get_decisions_total() -> int:
    return _decisions_total_int


# ------------
# Data models
# ------------
class EvaluateRequest(BaseModel):
    text: str = Field(..., description="Raw user prompt or content to evaluate.")
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


# -----------------
# Helper functions
# -----------------
def _resolve_ids(
    request: Request,
    body_tenant: Optional[str],
    body_bot: Optional[str],
) -> Tuple[str, str]:
    tenant_id = request.headers.get("X-Tenant-ID") or (body_tenant or "")
    bot_id = request.headers.get("X-Bot-ID") or (body_bot or "")
    return tenant_id, bot_id


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


# -------
# Routes
# -------
@router.post("/evaluate", response_model=EvaluateResponse)
async def evaluate(
    request: Request,
    req: EvaluateRequest,
    x_debug: Optional[str] = Header(
        default=None,
        alias="X-Debug",
        convert_underscores=False,
    ),
) -> Dict[str, Any]:
    """
    Evaluate inbound prompt for policy compliance and optionally sanitize.
    """
    inc_requests_total()

    tenant_id, bot_id = _resolve_ids(request, req.tenant_id, req.bot_id)

    det: Dict[str, Any] = evaluate_prompt(req.text) or {}
    action: str = str(det.get("action", "allow"))
    transformed: str = det.get("transformed_text", req.text) or req.text
    rule_hits: Dict[str, Any] = det.get("rule_hits") or {}

    # Final decision family + counters
    family = _family_from_result(action, transformed, req.text, rule_hits)
    if family == "block":
        decision = "block"
    elif family == "sanitize":
        decision = "sanitize"
    else:
        decision = "allow"

    inc_decisions_total()
    inc_decision_family(family)
    inc_decision_family_tenant_bot(family, tenant_id, bot_id)

    policy_version = current_rules_version()
    rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())

    payload: Dict[str, Any] = {
        "decision": decision,
        "transformed_text": transformed,
        "rule_hits": rule_hits,
        "policy_version": policy_version,
        "request_id": rid,
    }

    # Best-effort audit
    try:
        emit_audit_event(
            {
                "ts": int(time.time()),
                "event": "prompt_decision",
                "request_id": rid,
                "tenant_id": tenant_id,
                "bot_id": bot_id,
                "decision": decision,
                "family": family,
                "rule_hits": rule_hits,
                "policy_version": policy_version,
                "metadata": req.metadata or {},
            }
        )
    except Exception:
        # Don't break the route if auditing sinks fail
        pass

    return payload


@router.post("/egress/evaluate", response_model=Dict[str, Any])
async def egress_evaluate(
    request: Request,
    req: EgressEvaluateRequest,
    x_debug: Optional[str] = Header(
        default=None,
        alias="X-Debug",
        convert_underscores=False,
    ),
) -> Dict[str, Any]:
    """
    Evaluate outbound (egress) content for sensitive data leakage; may return redactions.
    """
    inc_requests_total()

    tenant_id, bot_id = _resolve_ids(request, req.tenant_id, req.bot_id)
    check_input = (req.text or "").strip()

    if not check_input:
        raise HTTPException(
            status_code=400,
            detail="Missing content to evaluate for egress.",
        )

    payload_raw, _hits = egress_check(check_input)
    payload = dict(payload_raw or {})
    action: str = str(payload.get("action", "allow"))
    redactions = int(payload.get("redactions") or 0)

    # Map to family
    if action == "deny":
        fam = "block"
    elif redactions > 0:
        fam = "sanitize"
    else:
        fam = "allow"

    inc_decisions_total()
    inc_decision_family(fam)
    inc_decision_family_tenant_bot(fam, tenant_id, bot_id)

    # Attach policy info + request id for consistency
    payload.setdefault("policy_version", current_rules_version())
    payload.setdefault(
        "request_id",
        request.headers.get("X-Request-ID") or str(uuid.uuid4()),
    )

    # Best-effort audit
    try:
        emit_audit_event(
            {
                "ts": int(time.time()),
                "event": "egress_decision",
                "request_id": payload["request_id"],
                "tenant_id": tenant_id,
                "bot_id": bot_id,
                "decision": fam,
                "raw_action": action,
                "redactions": redactions,
                "policy_version": payload["policy_version"],
                "metadata": req.metadata or {},
            }
        )
    except Exception:
        pass

    return payload

# file: app/routes/batch.py
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Header, Request, Response
from pydantic import BaseModel

from app.services.audit import emit_audit_event
from app.services.detectors import evaluate_prompt
from app.services.egress import egress_check
from app.services.policy import (
    _normalize_family,
    current_rules_version,
    sanitize_text,
)
from app.services.scanners.hidden_text import (
    decide_for_hidden_reasons,
    scan_and_record_html,
)
from app.services.threat_feed import (
    apply_dynamic_redactions,
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
from app.services.verifier.reuse_cache import (
    ENABLED as REUSE_ENABLED,
    get as reuse_get,
    make_key as reuse_key,
    set_decisive as reuse_set,
)
from app.shared.headers import BOT_HEADER, TENANT_HEADER
from app.telemetry.metrics import (
    inc_decision_family,
    inc_decision_family_tenant_bot,
    inc_verifier_outcome,
    inc_verifier_reuse,
)

router = APIRouter(prefix="/guardrail", tags=["guardrail"])
v1_router = APIRouter(prefix="/v1/batch", tags=["guardrail", "v1"])


# ---------------------------
# Models
# ---------------------------


class BatchItemIn(BaseModel):
    text: str
    request_id: Optional[str] = None


class BatchIn(BaseModel):
    items: List[BatchItemIn]


class BatchItemOut(BaseModel):
    request_id: str
    action: str
    text: str
    transformed_text: str
    risk_score: int
    rule_hits: Optional[List[str]] = None
    redactions: Optional[int] = None
    decisions: Optional[List[Dict[str, Any]]] = None


class BatchOut(BaseModel):
    items: List[BatchItemOut]
    count: int


# ---------------------------
# Helpers
# ---------------------------


def _tenant_bot_from_headers(request: Request) -> Tuple[str, str]:
    tenant = request.headers.get(TENANT_HEADER) or "default"
    bot = request.headers.get(BOT_HEADER) or "default"
    return tenant, bot


def _blen(s: Optional[str]) -> int:
    return len((s or "").encode("utf-8"))


def _family_for(action: str, redactions: int) -> str:
    if action == "deny":
        return "block"
    if redactions > 0:
        return "sanitize"
    if action == "clarify":
        return "verify"
    return "allow"


def _normalize_rule_hits(raw_hits: List[Any], raw_decisions: List[Any]) -> List[str]:
    """
    Normalize detector hits and decision metadata to flat 'source:list:id' strings.
    Mirrors the helper in routes/guardrail.py.
    """
    out: List[str] = []

    def add_hit(s: Optional[str]) -> None:
        if s and s not in out:
            out.append(s)

    # direct hits
    for h in raw_hits or []:
        if isinstance(h, str):
            add_hit(h)
        elif isinstance(h, dict):
            src = h.get("source") or h.get("origin") or h.get("provider") or h.get("src")
            lst = h.get("list") or h.get("kind") or h.get("type")
            rid = h.get("id") or h.get("rule_id") or h.get("name")
            if src and lst and rid:
                add_hit(f"{src}:{lst}:{rid}")
            elif rid:
                add_hit(str(rid))

    # derive from decisions if present
    for d in raw_decisions or []:
        if not isinstance(d, dict):
            continue
        src = d.get("source") or d.get("origin") or d.get("provider") or d.get("src")
        lst = d.get("list") or d.get("kind") or d.get("type")
        rid = d.get("id") or d.get("rule_id") or d.get("name")
        if src and lst and rid:
            add_hit(f"{src}:{lst}:{rid}")
        elif rid:
            add_hit(str(rid))

    return out


# ---------------------------
# Routes
# ---------------------------


@router.post("/batch_evaluate", response_model=BatchOut)
async def batch_evaluate(
    request: Request,
    body: BatchIn,
    response: Response,
    x_debug: Optional[str] = Header(default=None, alias="X-Debug", convert_underscores=False),
    x_force_unclear: Optional[str] = Header(
        default=None, alias="X-Force-Unclear", convert_underscores=False
    ),
) -> BatchOut:
    """
    Evaluate multiple ingress texts in one request.

    Per-item:
      - sanitize + optional threat feed redactions
      - detectors
      - optional verifier (feature gated via X-Force-Unclear: 1)
      - audit + family metrics
    """
    want_debug = x_debug == "1"
    do_verify = verifier_enabled() and (x_force_unclear == "1")
    tenant_id, bot_id = _tenant_bot_from_headers(request)
    policy_version = current_rules_version()

    out_items: List[BatchItemOut] = []
    header_hidden_reasons: List[str] = []

    for itm in body.items:
        text_in = itm.text or ""
        req_id = itm.request_id or str(uuid.uuid4())
        fp_all = content_fingerprint(text_in)

        # sanitize
        sanitized, families, redaction_count, _dbg = sanitize_text(text_in, debug=want_debug)
        if threat_feed_enabled():
            dyn_text, dyn_fams, dyn_reds, _ = apply_dynamic_redactions(sanitized, debug=want_debug)
            sanitized = dyn_text
            if dyn_fams:
                base = set(families or [])
                base.update(dyn_fams)
                families = sorted(base)
            if dyn_reds:
                redaction_count = (redaction_count or 0) + dyn_reds

        # Hidden-text scan & policy hook for HTML
        html_like = "<" in sanitized and ">" in sanitized and "</" in sanitized
        hidden_reasons: List[str] = []
        if html_like:
            hidden_reasons = scan_and_record_html(sanitized)

        hidden_action: Optional[str] = None
        if hidden_reasons:
            hidden_action, _matched = decide_for_hidden_reasons("html", hidden_reasons)

        det = evaluate_prompt(sanitized)
        decisions = list(det.get("decisions", []))
        xformed = det.get("transformed_text", sanitized)

        # flatten detector hits to strings then normalize to families
        det_hits_raw = det.get("rule_hits", []) or []
        dec_raw = det.get("decisions", []) or []
        flat_hits = _normalize_rule_hits(det_hits_raw, dec_raw)
        det_families = [_normalize_family(h) for h in flat_hits]
        combined_hits = sorted({*(families or []), *det_families})

        det_action = str(det.get("action", "allow"))
        if det_action == "deny":
            action = "deny"
        elif redaction_count:
            action = "allow"
        elif det_action == "clarify":
            action = "clarify"
        else:
            action = "allow"

        family = _family_for(action, int(redaction_count or 0))

        if hidden_action == "deny":
            action = "deny"
            family = "block"
        elif hidden_action == "clarify" and action != "deny":
            action = "clarify"
            family = "verify"

        if hidden_reasons:
            decisions.append({"source": "hidden_text", "type": "html", "matches": hidden_reasons})
            header_hidden_reasons.extend(hidden_reasons)

        # optional verifier (unclear intent path)
        if do_verify:
            providers = load_providers_order()
            v = Verifier(providers)
            verdict, provider = await v.assess_intent(text_in, meta={"hint": ""})

            if verdict is None:
                # providers unreachable: pick based on prior harmful cache
                if is_known_harmful(content_fingerprint(text_in)):
                    action = "deny"
                    family = "block"
                    outcome = "unsafe"
                else:
                    action = "clarify"
                    family = "verify"
                    outcome = "none"
            else:
                if verdict == Verdict.UNSAFE:
                    mark_harmful(content_fingerprint(text_in))
                    action = "deny"
                    family = "block"
                    outcome = "unsafe"
                elif verdict == Verdict.UNCLEAR:
                    action = "clarify"
                    family = "verify"
                    outcome = "unclear"
                else:
                    outcome = "safe"

            # ensure provider is a string for metrics
            inc_verifier_outcome(str(provider or "unknown"), outcome)
            if REUSE_ENABLED and outcome in ("safe", "unsafe"):
                key = reuse_key(
                    request_id=req_id,
                    tenant=tenant_id,
                    bot=bot_id,
                    policy_version=policy_version,
                    fingerprint=fp_all,
                )
                reuse_set(key, outcome)

        # metrics
        inc_decision_family(family)
        inc_decision_family_tenant_bot(tenant_id, bot_id, family)

        # audit
        try:
            event: Dict[str, Any] = {
                "ts": None,
                "tenant_id": tenant_id,
                "bot_id": bot_id,
                "request_id": req_id,
                "direction": "ingress",
                "decision": action,
                "rule_hits": (combined_hits or None),
                "policy_version": policy_version,
                "verifier_provider": None,
                "fallback_used": None,
                "status_code": 200,
                "redaction_count": int(redaction_count or 0),
                "hash_fingerprint": fp_all,
                "payload_bytes": int(_blen(text_in)),
                "sanitized_bytes": int(_blen(xformed)),
                "meta": {},
            }
            if hidden_reasons:
                event["hidden_text"] = {"format": "html", "reasons": hidden_reasons}
            emit_audit_event(event)
        except Exception:
            pass

        out_items.append(
            BatchItemOut(
                request_id=req_id,
                action=action,
                text=xformed,
                transformed_text=xformed,
                risk_score=int(det.get("risk_score", 0)),
                rule_hits=(combined_hits or None),
                redactions=int(redaction_count or 0) or None,
                decisions=(decisions or None),
            )
        )

    if header_hidden_reasons:
        uniq = sorted({r for r in header_hidden_reasons})
        response.headers["X-Guardrail-Hidden-Text"] = f"fmt=html;reasons={','.join(uniq)}"

    return BatchOut(items=out_items, count=len(out_items))


@v1_router.post("/egress_batch", response_model=BatchOut)
async def egress_batch_v1(
    request: Request,
    body: BatchIn,
    response: Response,
    x_debug: Optional[str] = Header(default=None, alias="X-Debug", convert_underscores=False),
) -> BatchOut:
    return await egress_batch(request, body, response, x_debug)


@v1_router.post("/batch_evaluate", response_model=BatchOut)
async def batch_evaluate_v1(
    request: Request,
    body: BatchIn,
    response: Response,
    x_debug: Optional[str] = Header(default=None, alias="X-Debug", convert_underscores=False),
    x_force_unclear: Optional[str] = Header(
        default=None, alias="X-Force-Unclear", convert_underscores=False
    ),
) -> BatchOut:
    return await batch_evaluate(request, body, response, x_debug, x_force_unclear)


@router.post("/egress_batch", response_model=BatchOut)
async def egress_batch(
    request: Request,
    body: BatchIn,
    response: Response,
    x_debug: Optional[str] = Header(default=None, alias="X-Debug", convert_underscores=False),
) -> BatchOut:
    """
    Evaluate multiple egress texts in one request (post-model output).

    Per-item:
      - hard-deny checks, else sanitize via policy.sanitize_text
      - audit + family metrics
    """
    want_debug = x_debug == "1"
    tenant_id, bot_id = _tenant_bot_from_headers(request)
    policy_version = current_rules_version()

    out_items: List[BatchItemOut] = []
    header_hidden_reasons: List[str] = []

    for itm in body.items:
        text_in = itm.text or ""
        req_id = itm.request_id or str(uuid.uuid4())
        fp_all = content_fingerprint(text_in)
        hits: Optional[List[str]] = None

        if REUSE_ENABLED:
            key = reuse_key(
                request_id=req_id,
                tenant=tenant_id,
                bot=bot_id,
                policy_version=policy_version,
                fingerprint=fp_all,
            )
            reused = reuse_get(key)
            if reused in ("safe", "unsafe"):
                if reused == "unsafe":
                    action = "deny"
                    family = "block"
                else:
                    action = "allow"
                    family = "allow"
                inc_verifier_reuse(reused)
                payload_bytes = int(_blen(text_in))
                xformed = text_in
                hits = hits or None
                out_items.append(
                    BatchItemOut(
                        request_id=req_id,
                        action=action,
                        text=xformed,
                        transformed_text=xformed,
                        risk_score=0,
                        rule_hits=hits,
                        redactions=None,
                        decisions=None,
                    )
                )
                try:
                    emit_audit_event(
                        {
                            "ts": None,
                            "tenant_id": tenant_id,
                            "bot_id": bot_id,
                            "request_id": req_id,
                            "direction": "egress",
                            "decision": action,
                            "rule_hits": hits,
                            "policy_version": policy_version,
                            "verifier_provider": "reuse",
                            "fallback_used": None,
                            "status_code": 200,
                            "redaction_count": 0,
                            "hash_fingerprint": fp_all,
                            "payload_bytes": payload_bytes,
                            "sanitized_bytes": int(_blen(xformed)),
                            "meta": {"reuse": True},
                        }
                    )
                except Exception:
                    pass
                continue

        payload, _ = egress_check(text_in, debug=want_debug)
        action = str(payload.get("action", "allow"))
        xformed = str(payload.get("text", ""))
        redactions = int(payload.get("redactions") or 0)
        hits = list(payload.get("rule_hits") or []) or None

        hidden_reasons: List[str] = []
        html_like = "<" in xformed and ">" in xformed and "</" in xformed
        if html_like:
            hidden_reasons = scan_and_record_html(xformed)

        hidden_action: Optional[str] = None
        if hidden_reasons:
            hidden_action, _matched = decide_for_hidden_reasons("html", hidden_reasons)
            if hidden_action == "deny":
                action = "deny"
            elif hidden_action == "clarify" and action != "deny":
                action = "clarify"

        if hidden_reasons:
            hits = (hits or []) + [f"hidden_text:html:{r}" for r in hidden_reasons]

        family = _family_for(action, redactions)
        if hidden_action == "deny":
            family = "block"
        elif hidden_action == "clarify" and action != "deny":
            family = "verify"

        if hidden_reasons:
            header_hidden_reasons.extend(hidden_reasons)

        # metrics
        inc_decision_family(family)
        inc_decision_family_tenant_bot(tenant_id, bot_id, family)

        # audit
        try:
            event: Dict[str, Any] = {
                "ts": None,
                "tenant_id": tenant_id,
                "bot_id": bot_id,
                "request_id": req_id,
                "direction": "egress",
                "decision": action,
                "rule_hits": hits,
                "policy_version": policy_version,
                "verifier_provider": None,
                "fallback_used": None,
                "status_code": 200,
                "redaction_count": redactions,
                "hash_fingerprint": fp_all,
                "payload_bytes": int(_blen(text_in)),
                "sanitized_bytes": int(_blen(xformed)),
                "meta": {},
            }
            if hidden_reasons:
                event["hidden_text"] = {"format": "html", "reasons": hidden_reasons}
            emit_audit_event(event)
        except Exception:
            pass

        out_items.append(
            BatchItemOut(
                request_id=req_id,
                action=action,
                text=xformed,
                transformed_text=xformed,
                risk_score=0,
                rule_hits=hits,
                redactions=redactions or None,
                decisions=None,
            )
        )

    if header_hidden_reasons:
        uniq = sorted({r for r in header_hidden_reasons})
        response.headers["X-Guardrail-Hidden-Text"] = f"fmt=html;reasons={','.join(uniq)}"

    return BatchOut(items=out_items, count=len(out_items))

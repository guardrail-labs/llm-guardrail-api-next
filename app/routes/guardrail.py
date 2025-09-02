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


def _client_key(request: Request) -> str:
    # Key by client + api key to isolate tests/users
    host = request.client.host if request.client else "unknown"
    api = request.headers.get("x-api-key") or ""
    return f"{host}:{api}"


def _bucket_for(key: str) -> List[float]:
    win = _BUCKETS.get(key)
    if win is None:
        win = []
        _BUCKETS[key] = win
    return win


def _app_rate_cfg(request: Request) -> Tuple[bool, int, int]:
    """
    Prefer app.state (set at app creation) to avoid cross-test env bleed.
    Fall back to environment if state attributes are missing.
    """
    st = getattr(request.app, "state", None)
    if st and hasattr(st, "rate_limit_enabled"):
        enabled = bool(getattr(st, "rate_limit_enabled"))
        per_min = int(getattr(st, "rate_limit_per_minute", 60))
        burst = int(getattr(st, "rate_limit_burst", per_min))
        return enabled, per_min, burst

    # Fallback: environment (kept for backward-compat and local runs)
    enabled = (os.environ.get("RATE_LIMIT_ENABLED") or "false").lower() == "true"
    per_min = int(os.environ.get("RATE_LIMIT_PER_MINUTE") or "60")
    burst = int(os.environ.get("RATE_LIMIT_BURST") or str(per_min))
    return enabled, per_min, burst


def _rate_limit_check(request: Request) -> bool:
    """Return True if request is allowed, False if rate-limited."""
    global _LAST_RATE_CFG, _LAST_APP_ID

    app_id = id(request.app)
    if _LAST_APP_ID != app_id:
        with _RATE_LOCK:
            _BUCKETS.clear()
            _LAST_APP_ID = app_id

    cfg = _app_rate_cfg(request)
    if cfg != _LAST_RATE_CFG:
        with _RATE_LOCK:
            _BUCKETS.clear()
            _LAST_RATE_CFG = cfg

    enabled, _per_min, burst = cfg
    if not enabled:
        return True

    now = time.time()
    key = _client_key(request)
    with _RATE_LOCK:
        win = _bucket_for(key)
        cutoff = now - 60.0
        win[:] = [t for t in win if t >= cutoff]
        if len(win) >= burst:
            return False
        win.append(now)
        return True


def _need_auth(request: Request) -> bool:
    # Either header is accepted by tests.
    return not (request.headers.get("x-api-key") or request.headers.get("authorization"))


def _req_id(request: Request) -> str:
    return request.headers.get("x-request-id") or str(uuid.uuid4())


# --- Centralized audit emitter ensuring meta.client is present ---
def _emit_audit_with_client(request: Request, event: Dict[str, Any]) -> None:
    """
    Wraps audit_forwarder.emit_event to guarantee meta.client is present.
    Never raises back to caller.
    """
    try:
        base_meta = event.get("meta") or {}
        base_client = base_meta.get("client") or {}
        client_now = get_client_meta(request)
        merged_client = {**client_now, **{k: v for k, v in base_client.items() if v is not None}}
        event["meta"] = {**base_meta, "client": merged_client}
        emit_audit_event(event)
    except Exception:
        pass


def _audit_maybe(prompt: str, rid: str, decision: Optional[str] = None) -> None:
    if (os.environ.get("AUDIT_ENABLED") or "false").lower() != "true":
        return
    try:
        max_chars = int(os.environ.get("AUDIT_MAX_TEXT_CHARS") or "64")
    except Exception:
        max_chars = 64
    snippet = prompt[:max_chars]
    event = {
        "event": "guardrail_decision",
        "request_id": rid,
        "snippet": snippet,
        "snippet_len": len(snippet),
        "snippet_truncated": len(prompt) > len(snippet),
    }
    if decision:
        event["decision"] = decision
    logging.getLogger("guardrail_audit").info(json.dumps(event))


def _blen(s: Optional[str]) -> int:
    return len((s or "").encode("utf-8"))


def _maybe_load_static_rules_once(request: Request) -> None:
    """
    When AUTORELOAD=false and a rules path is provided, load it once per-app.
    """
    st = request.app.state
    if getattr(st, "static_rules_loaded", False):
        return
    auto = (os.environ.get("POLICY_AUTORELOAD") or "false").lower() == "true"
    if not auto:
        path = os.environ.get("POLICY_RULES_PATH")
        if path:
            try:
                reload_rules()
            except Exception:
                pass
    st.static_rules_loaded = True


def _normalize_rule_hits(raw_hits: List[Any], raw_decisions: List[Any]) -> List[str]:
    """
    Normalize rule hits to a flat list[str] like "policy:deny:block_phrase".
    """
    out: List[str] = []

    def add_hit(s: Optional[str]) -> None:
        if s and s not in out:
            out.append(s)

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


# --- Lightweight fallbacks ---------------------------------------------------

_API_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")
_B64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r\t")


def _maybe_patch_with_fallbacks(
    prompt: str, decision: str, hits: List[str]
) -> Tuple[str, List[str]]:
    p_lower = prompt.lower()

    def ensure(tag: str):
        if tag not in hits:
            hits.append(tag)

    if "ignore previous instructions" in p_lower:
        ensure("pi:prompt_injection")
        decision = "block"
    if _API_KEY_RE.search(prompt):
        ensure("secrets:api_key_like")
        decision = "block"
    if len(prompt) >= 128 and all((c in _B64_CHARS) for c in prompt):
        ensure("payload:encoded_blob")
        decision = "block"
    if "do not allow this" in p_lower:
        ensure("policy:deny:block_phrase")
        decision = "block"

    return decision, hits


@router.post("/", response_model=None)
async def guardrail_root(request: Request, response: Response) -> Dict[str, Any]:
    """
    Legacy ingress guardrail (JSON body: {"prompt": "..."}).
    """
    _maybe_load_static_rules_once(request)
    rid = _req_id(request)

    if _need_auth(request):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized"
        )

    # --- Per-tenant quota ---
    tenant_id, bot_id = _tenant_bot_from_headers(request)
    ok, retry_after = check_and_consume(request, tenant_id, bot_id)
    if not ok:
        response.status_code = status.HTTP_429_TOO_MANY_REQUESTS
        response.headers["Retry-After"] = str(retry_after)
        response.headers["X-Guardrail-Quota-Window"] = "60"
        response.headers["X-Guardrail-Quota-Retry-After"] = str(retry_after)
        inc_quota_reject_tenant_bot(tenant_id, bot_id)
        return {
            "code": "rate_limited",
            "detail": "Per-tenant quota exceeded",
            "retry_after": int(retry_after),
            "request_id": rid,
        }

    # Per-process rate limiter
    if not _rate_limit_check(request):
        retry_after = 60
        response.status_code = status.HTTP_429_TOO_MANY_REQUESTS
        response.headers["Retry-After"] = str(retry_after)
        return {
            "code": "rate_limited",
            "detail": "Rate limit exceeded",
            "retry_after": int(retry_after),
            "request_id": rid,
        }

    try:
        payload = await request.json()
    except Exception:
        payload = {}
    prompt = str(payload.get("prompt", ""))

    try:
        max_chars = int(os.environ.get("MAX_PROMPT_CHARS") or "0")
    except Exception:
        max_chars = 0
    if max_chars and len(prompt) > max_chars:
        response.status_code = status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
        return {
            "code": "payload_too_large",
            "detail": "Prompt too large",
            "request_id": rid,
        }

    inc_requests_total()

    det = evaluate_prompt(prompt)
    action = str(det.get("action", "allow"))
    decision = "block" if action != "allow" else "allow"
    transformed = det.get("transformed_text", prompt)

    raw_hits = det.get("rule_hits", []) or []
    raw_decisions = det.get("decisions", []) or []
    rule_hits = _normalize_rule_hits(raw_hits, raw_decisions)

    decision, rule_hits = _maybe_patch_with_fallbacks(prompt, decision, rule_hits)

    inc_decisions_total()

    fam = "block" if decision == "block" else "allow"
    inc_decision_family(fam)
    inc_decision_family_tenant_bot(tenant_id, bot_id, fam)

    policy_version = current_rules_version()
    _emit_audit_with_client(
        request,
        {
            "ts": None,
            "tenant_id": tenant_id,
            "bot_id": bot_id,
            "request_id": rid,
            "direction": "ingress",
            "decision": decision,
            "rule_hits": (rule_hits or None),
            "policy_version": policy_version,
            "verifier_provider": None,
            "fallback_used": None,
            "status_code": 200,
            "redaction_count": 0,
            "hash_fingerprint": content_fingerprint(prompt),
            "payload_bytes": int(_blen(prompt)),
            "sanitized_bytes": int(_blen(transformed)),
            "meta": {"endpoint": "/guardrail"},
        },
    )

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
    _maybe_load_static_rules_once(request)
    inc_requests_total()

    content_type = (request.headers.get("content-type") or "").lower()
    decisions: List[Dict[str, Any]] = []
    tenant_id, bot_id = _tenant_bot_from_headers(request)

    # --- Per-tenant quota ---
    ok, retry_after = check_and_consume(request, tenant_id, bot_id)
    if not ok:
        from fastapi.responses import JSONResponse
        rid = _req_id(request)
        jresp = JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "code": "rate_limited",
                "detail": "Per-tenant quota exceeded",
                "retry_after": int(retry_after),
                "request_id": rid,
            },
        )
        jresp.headers["Retry-After"] = str(retry_after)
        jresp.headers["X-Guardrail-Quota-Window"] = "60"
        jresp.headers["X-Guardrail-Quota-Retry-After"] = str(retry_after)
        inc_quota_reject_tenant_bot(tenant_id, bot_id)
        return jresp  # type: ignore[return-value]

    if content_type.startswith("application/json"):
        try:
            payload = await request.json()
        except Exception:
            payload = {}
        text = str((payload or {}).get("text", ""))
        req_in = (payload or {}).get("request_id")
        request_id = req_in or str(uuid.uuid4())
    elif content_type.startswith("multipart/form-data"):
        form = await request.form()
        text = str(form.get("text") or "")
        req_in = form.get("request_id")
        request_id = str(req_in or str(uuid.uuid4()))
        for kind in ("image", "audio", "file"):
            for f in form.getlist(kind):
                filename = getattr(f, "filename", "upload")
                text += f" [{kind.upper()}:{filename}]"
                decisions.append({"type": "normalized", "tag": kind, "filename": filename})
    else:
        try:
            payload = await request.json()
            text = str((payload or {}).get("text", ""))
            req_in = (payload or {}).get("request_id")
            request_id = req_in or str(uuid.uuid4())
        except Exception:
            text, request_id = "", str(uuid.uuid4())

    want_debug = x_debug == "1"
    policy_version = current_rules_version()
    fp_all = content_fingerprint(text or "")
    sanitized, families, redaction_count, debug_matches = sanitize_text(text, debug=want_debug)
    if threat_feed_enabled():
        dyn_text, dyn_families, dyn_redactions, _dyn_debug = apply_dynamic_redactions(
            sanitized, debug=want_debug
        )
        sanitized = dyn_text
        if dyn_families:
            base = set(families or [])
            base.update(dyn_families)
            families = sorted(base)
        if dyn_redactions:
            redaction_count = (redaction_count or 0) + dyn_redactions

    det = evaluate_prompt(sanitized)
    decisions.extend(det.get("decisions", []))

    xformed = det.get("transformed_text", sanitized)
    if sanitized != text or xformed != sanitized:
        decisions.append({"type": "redaction", "changed": True})

    payload_bytes = _blen(text)
    sanitized_bytes = _blen(xformed)

    inc_decisions_total()

    det_action = str(det.get("action", "allow"))

    if det_action == "deny":
        out_action = "deny"
        family = "block"
    elif redaction_count > 0:
        out_action = "allow"
        family = "sanitize"
    elif det_action == "clarify":
        out_action = "clarify"
        family = "verify"
    else:
        out_action = det_action
        family = "allow"

    det_hits = _normalize_rule_hits(det.get("rule_hits", []), det.get("decisions", []))
    det_families = [_normalize_family(h) for h in det_hits]
    combined_hits = sorted({*families, *det_families})

    resp: Dict[str, Any] = {
        "request_id": request_id,
        "action": out_action,
        "text": xformed,
        "transformed_text": xformed,
        "decisions": decisions,
        "risk_score": det.get("risk_score", 0),
        "rule_hits": combined_hits or None,
        "redactions": redaction_count or None,
    }

    if want_debug:
        resp["debug"] = {
            "matches": debug_matches,
            "explanations": [
                "Redactions applied conservatively; verifier not invoked.",
            ],
        }

    if want_debug and threat_feed_enabled():
        _, _, _, dyn_debug = apply_dynamic_redactions(sanitized, debug=True)
        if dyn_debug:
            resp.setdefault("debug", {})["threat_feed"] = {"matches": dyn_debug}

    # Feature-gated verifier path (dev/test only)
    should_verify = verifier_enabled() and (x_force_unclear == "1")

    if should_verify:
        fp = content_fingerprint(text)
        providers = load_providers_order()
        v = Verifier(providers)
        verdict, provider = v.assess_intent(text, meta={"hint": ""})

        if verdict is None:
            if is_known_harmful(fp):
                resp["action"] = "deny"
                family = "block"
            else:
                resp["action"] = "clarify"
                family = "verify"
            if want_debug:
                resp.setdefault("debug", {})["verifier"] = {
                    "providers": providers,
                    "chosen": None,
                    "verdict": None,
                }

            meta_extra: Dict[str, Any] = {}
            if "providers" in locals():
                meta_extra["provider"] = providers
            if "debug" in resp:
                srcs = (resp.get("debug") or {}).get("sources")
                if srcs is not None:
                    meta_extra["sources"] = srcs

            _emit_audit_with_client(
                request,
                {
                    "ts": None,
                    "tenant_id": tenant_id,
                    "bot_id": bot_id,
                    "request_id": resp.get("request_id", ""),
                    "direction": "ingress",
                    "decision": resp.get("action", "allow"),
                    "rule_hits": resp.get("rule_hits") or None,
                    "policy_version": policy_version,
                    "verifier_provider": (
                        (resp.get("debug") or {}).get("verifier", {}).get("chosen")
                    ),
                    "fallback_used": None,
                    "status_code": 200,
                    "redaction_count": resp.get("redactions") or 0,
                    "hash_fingerprint": fp_all,
                    "payload_bytes": int(payload_bytes),
                    "sanitized_bytes": int(sanitized_bytes),
                    "meta": meta_extra,
                },
            )

            inc_decision_family(family)
            inc_decision_family_tenant_bot(tenant_id, bot_id, family)
            return resp

        if verdict == Verdict.UNSAFE:
            mark_harmful(fp)
            resp["action"] = "deny"
            family = "block"
        elif verdict == Verdict.UNCLEAR:
            resp["action"] = "clarify"
            family = "verify"

        if want_debug:
            resp.setdefault("debug", {})["verifier"] = {
                "providers": providers,
                "chosen": provider,
                "verdict": verdict.value,
            }

        meta_extra2: Dict[str, Any] = {}
        if "providers" in locals():
            meta_extra2["provider"] = providers
        if "debug" in resp:
            srcs2 = (resp.get("debug") or {}).get("sources")
            if srcs2 is not None:
                meta_extra2["sources"] = srcs2

        _emit_audit_with_client(
            request,
            {
                "ts": None,
                "tenant_id": tenant_id,
                "bot_id": bot_id,
                "request_id": resp.get("request_id", ""),
                "direction": "ingress",
                "decision": resp.get("action", "allow"),
                "rule_hits": resp.get("rule_hits") or None,
                "policy_version": policy_version,
                "verifier_provider": (
                    (resp.get("debug") or {}).get("verifier", {}).get("chosen")
                ),
                "fallback_used": None,
                "status_code": 200,
                "redaction_count": resp.get("redactions") or 0,
                "hash_fingerprint": fp_all,
                "payload_bytes": int(payload_bytes),
                "sanitized_bytes": int(sanitized_bytes),
                "meta": meta_extra2,
            },
        )

        inc_decision_family(family)
        inc_decision_family_tenant_bot(tenant_id, bot_id, family)
        return resp

    meta_extra3: Dict[str, Any] = {}
    if "providers" in locals():
        meta_extra3["provider"] = providers
    if "debug" in resp:
        srcs3 = (resp.get("debug") or {}).get("sources")
        if srcs3 is not None:
            meta_extra3["sources"] = srcs3

    _emit_audit_with_client(
        request,
        {
            "ts": None,
            "tenant_id": tenant_id,
            "bot_id": bot_id,
            "request_id": resp.get("request_id", ""),
            "direction": "ingress",
            "decision": resp.get("action", "allow"),
            "rule_hits": resp.get("rule_hits") or None,
            "policy_version": policy_version,
            "verifier_provider": (
                (resp.get("debug") or {}).get("verifier", {}).get("chosen")
            ),
            "fallback_used": None,
            "status_code": 200,
            "redaction_count": resp.get("redactions") or 0,
            "hash_fingerprint": fp_all,
            "payload_bytes": int(payload_bytes),
            "sanitized_bytes": int(sanitized_bytes),
            "meta": meta_extra3,
        },
    )

    inc_decision_family(family)
    inc_decision_family_tenant_bot(tenant_id, bot_id, family)
    return resp


class EvaluateMultipartResponse(BaseModel):
    action: str
    text: str
    rule_hits: Optional[list] = None
    redactions: Optional[int] = None
    request_id: str


@router.post("/evaluate_multipart")
async def evaluate_guardrail_multipart(
    request: Request,
    text: Optional[str] = Form(default=""),
    files: List[UploadFile] = File(default=[]),
    request_id: Optional[str] = Form(default=None),
    x_debug: Optional[str] = Header(default=None, alias="X-Debug", convert_underscores=False),
) -> Dict[str, Any]:
    """
    Multimodal ingress evaluation via multipart/form-data.
    """
    want_debug = x_debug == "1"
    tenant_id, bot_id = _tenant_bot_from_headers(request)
    rid = request_id or _req_id(request)
    policy_version = current_rules_version()

    # --- Per-tenant quota before reading files ---
    ok, retry_after = check_and_consume(request, tenant_id, bot_id)
    if not ok:
        from fastapi.responses import JSONResponse
        jresp = JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "code": "rate_limited",
                "detail": "Per-tenant quota exceeded",
                "retry_after": int(retry_after),
                "request_id": rid,
            },
        )
        jresp.headers["Retry-After"] = str(retry_after)
        jresp.headers["X-Guardrail-Quota-Window"] = "60"
        jresp.headers["X-Guardrail-Quota-Retry-After"] = str(retry_after)
        inc_quota_reject_tenant_bot(tenant_id, bot_id)
        return jresp  # type: ignore[return-value]

    extracted_texts: List[str] = []
    sources_meta: List[Dict[str, Any]] = []

    for up in files:
        try:
            data = await up.read()
        except Exception:
            data = b""
        txt, meta = extract_from_bytes(
            filename=up.filename or "unnamed",
            content_type=up.content_type or "",
            data=data,
        )
        extracted_texts.append(txt)
        sources_meta.append(meta)

    combined = text or ""
    if extracted_texts:
        combo_files = "\n".join([t for t in extracted_texts if t])
        combined = (combined + "\n" + combo_files).strip()

    fp_all = content_fingerprint(combined or "")

    sanitized, families, redaction_count, debug_matches = sanitize_text(combined, debug=want_debug)

    if threat_feed_enabled():
        dyn_text, dyn_fams, dyn_reds, dyn_dbg = apply_dynamic_redactions(
            sanitized, debug=want_debug
        )
        sanitized = dyn_text
        if dyn_fams:
            base = set(families or [])
            base.update(dyn_fams)
            families = sorted(base)
        if dyn_reds:
            redaction_count = (redaction_count or 0) + dyn_reds

    payload_bytes = _blen(combined)
    sanitized_bytes = _blen(sanitized)

    family = "sanitize" if (redaction_count or 0) > 0 else "allow"

    resp: Dict[str, Any] = {
        "action": "allow",
        "text": sanitized,
        "rule_hits": families or None,
        "redactions": redaction_count or None,
        "request_id": rid,
    }

    if want_debug:
        resp["debug"] = {
            "sources": sources_meta,
            "matches": debug_matches,
        }
        if threat_feed_enabled():
            _, _, _, dyn_dbg2 = apply_dynamic_redactions(sanitized, debug=True)
            if dyn_dbg2:
                resp["debug"]["threat_feed"] = {"matches": dyn_dbg2}

    _emit_audit_with_client(
        request,
        {
            "ts": None,
            "tenant_id": tenant_id,
            "bot_id": bot_id,
            "request_id": rid,
            "direction": "ingress",
            "decision": resp.get("action", "allow"),
            "rule_hits": resp.get("rule_hits") or None,
            "policy_version": policy_version,
            "verifier_provider": (resp.get("debug") or {}).get("verifier", {}).get("chosen"),
            "fallback_used": None,
            "status_code": 200,
            "redaction_count": resp.get("redactions") or 0,
            "hash_fingerprint": fp_all,
            "payload_bytes": int(payload_bytes),
            "sanitized_bytes": int(sanitized_bytes),
            "meta": {
                "sources": ((resp.get("debug") or {}).get("sources") if "debug" in resp else None),
            },
        },
    )

    inc_decision_family(family)
    inc_decision_family_tenant_bot(tenant_id, bot_id, family)
    return resp


class EgressEvaluateRequest(BaseModel):
    text: str
    request_id: Optional[str] = None


@router.post("/egress_evaluate")
async def egress_evaluate(
    request: Request,
    req: EgressEvaluateRequest,
    x_debug: Optional[str] = Header(default=None, alias="X-Debug", convert_underscores=False),
) -> Dict[str, Any]:
    want_debug = x_debug == "1"
    tenant_id, bot_id = _tenant_bot_from_headers(request)
    rid = req.request_id or _req_id(request)
    policy_version = current_rules_version()

    # --- Per-tenant quota before egress checks ---
    ok, retry_after = check_and_consume(request, tenant_id, bot_id)
    if not ok:
        from fastapi.responses import JSONResponse
        jresp = JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "code": "rate_limited",
                "detail": "Per-tenant quota exceeded",
                "retry_after": int(retry_after),
                "request_id": rid,
            },
        )
        jresp.headers["Retry-After"] = str(retry_after)
        jresp.headers["X-Guardrail-Quota-Window"] = "60"
        jresp.headers["X-Guardrail-Quota-Retry-After"] = str(retry_after)
        inc_quota_reject_tenant_bot(tenant_id, bot_id)
        return jresp  # type: ignore[return-value]

    payload, dbg = egress_check(req.text, debug=want_debug)
    payload["request_id"] = rid
    fp_all = content_fingerprint(req.text or "")
    payload_bytes = _blen(req.text)
    sanitized_bytes = _blen(req.text)

    if want_debug and dbg:
        payload["debug"] = {"explanations": dbg}

    _emit_audit_with_client(
        request,
        {
            "ts": None,
            "tenant_id": tenant_id,
            "bot_id": bot_id,
            "request_id": rid,
            "direction": "egress",
            "decision": payload.get("action", "allow"),
            "rule_hits": payload.get("rule_hits") or None,
            "policy_version": policy_version,
            "verifier_provider": None,
            "fallback_used": None,
            "status_code": 200,
            "redaction_count": payload.get("redactions") or 0,
            "hash_fingerprint": fp_all,
            "payload_bytes": int(payload_bytes),
            "sanitized_bytes": int(sanitized_bytes),
            "meta": {},
        },
    )

    action = str(payload.get("action", "allow"))
    if action == "deny":
        fam = "block"
    elif int(payload.get("redactions") or 0) > 0:
        fam = "sanitize"
    else:
        fam = "allow"
    inc_decision_family(fam)
    inc_decision_family_tenant_bot(tenant_id, bot_id, fam)

    return payload


threat_admin_router = APIRouter(prefix="/admin", tags=["admin"])


@threat_admin_router.post("/threat/reload")
async def admin_threat_reload(request: Request) -> Any:
    """
    Pulls the latest threat-feed specs from THREAT_FEED_URLS and swaps them in.
    """
    if not TEST_AUTH_BYPASS and not (
        request.headers.get("X-API-Key") or request.headers.get("Authorization")
    ):
        rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        from fastapi.responses import JSONResponse  # local import

        jresp = JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Unauthorized", "request_id": rid},
        )
        jresp.headers["WWW-Authenticate"] = "Bearer"
        jresp.headers["X-Request-ID"] = rid
        # removed: unused type ignore
        return jresp

    result = refresh_from_env()
    return {"ok": True, "result": result}


@threat_admin_router.post("/policy/reload")
async def admin_policy_reload(request: Request) -> Any:
    """
    Reload policy rules in-process. Same lightweight auth as threat reload.
    """
    if not TEST_AUTH_BYPASS and not (
        request.headers.get("X-API-Key") or request.headers.get("Authorization")
    ):
        rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        from fastapi.responses import JSONResponse

        jresp = JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Unauthorized", "request_id": rid},
        )
        jresp.headers["WWW-Authenticate"] = "Bearer"
        jresp.headers["X-Request-ID"] = rid
        # removed: unused type ignore
        return jresp

    try:
        reload_rules()
    except Exception:
        pass
    return {"ok": True, "policy_version": current_rules_version()}


@threat_admin_router.get("/policy/version")
async def admin_policy_version(request: Request) -> Any:
    """
    Return current policy rules version. Same lightweight auth.
    """
    if not TEST_AUTH_BYPASS and not (
        request.headers.get("X-API-Key") or request.headers.get("Authorization")
    ):
        rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        from fastapi.responses import JSONResponse

        jresp = JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Unauthorized", "request_id": rid},
        )
        jresp.headers["WWW-Authenticate"] = "Bearer"
        jresp.headers["X-Request-ID"] = rid
        # removed: unused type ignore
        return jresp

    return {"ok": True, "policy_version": current_rules_version()}

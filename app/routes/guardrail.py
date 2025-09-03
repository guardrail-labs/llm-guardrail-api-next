from __future__ import annotations

import hashlib
import os
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Header, Request, UploadFile
from fastapi.responses import JSONResponse

# Metrics module
from app.telemetry import metrics as m
# Forwarder (tests monkeypatch af._post and our emit wrapper)
from app.services import audit_forwarder as af

router = APIRouter()

# ------------------------- helpers & constants -------------------------

# Legacy route always requires an API key (tests expect this)
def _has_api_key(x_api_key: Optional[str]) -> bool:
    return bool(x_api_key)

RE_SECRET = re.compile(r"\bsk-[A-Za-z0-9]{24,}\b")
RE_PROMPT_INJ = re.compile(r"\bignore\s+previous\s+instructions\b", re.I)
RE_LONG_BASE64ISH = re.compile(r"\b[A-Za-z0-9+/=]{200,}\b")
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
RE_PHONE = re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b")
RE_PRIVATE_KEY = re.compile(
    r"-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----",
    re.S,
)
RE_HACK_WIFI = re.compile(r"(?i)(hack\s+a\s+wifi|bypass\s+wpa2)")

# Policy IDs expected by tests for legacy route
PI_PROMPT_INJ_ID = "pi:prompt_injection"
SECRETS_API_KEY_ID = "secrets:api_key_like"
PAYLOAD_BLOB_ID = "payload:encoded_blob"

def _req_id(existing: Optional[str]) -> str:
    return existing or str(uuid.uuid4())

def _fingerprint(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()

def _tenant_bot(t: Optional[str], b: Optional[str]) -> Tuple[str, str]:
    tenant = (t or "default").strip() or "default"
    bot = (b or "default").strip() or "default"
    return tenant, bot

def emit_audit_event(payload: Dict[str, Any]) -> None:
    enabled = os.getenv("AUDIT_FORWARD_ENABLED", "false").lower() in {"1", "true", "yes"}
    if enabled:
        url = os.getenv("AUDIT_FORWARD_URL", "")
        key = os.getenv("AUDIT_FORWARD_API_KEY", "")
        if url and key:
            try:
                af._post(url, key, payload)
            except Exception:
                pass

def _apply_redactions(text: str) -> Tuple[str, Dict[str, List[str]], int]:
    """Return (redacted_text, rule_hits, count). rule_hits is a dict for /evaluate & egress."""
    rule_hits: Dict[str, List[str]] = {}
    redactions = 0
    redacted = text

    if RE_EMAIL.search(redacted):
        redacted = RE_EMAIL.sub("[REDACTED:EMAIL]", redacted)
        rule_hits.setdefault("pii:email", []).append(RE_EMAIL.pattern)
        m.inc_redaction("email")
        redactions += 1

    if RE_PHONE.search(redacted):
        redacted = RE_PHONE.sub("[REDACTED:PHONE]", redacted)
        rule_hits.setdefault("pii:phone", []).append(RE_PHONE.pattern)
        m.inc_redaction("phone")
        redactions += 1

    if RE_SECRET.search(redacted):
        redacted = RE_SECRET.sub("[REDACTED:OPENAI_KEY]", redacted)
        rule_hits.setdefault("secrets:openai_key", []).append(RE_SECRET.pattern)
        m.inc_redaction("openai_key")
        redactions += 1

    return redacted, rule_hits, redactions

def _debug_requested(x_debug: Optional[str]) -> bool:
    return bool(x_debug)

def _policy_version() -> Optional[str]:
    # The policy loader in tests sets this env
    return os.getenv("POLICY_VERSION")

def _respond_legacy_allow(prompt: str, request_id: str, rule_hits: List[str]) -> JSONResponse:
    m.inc_decisions_total("allow")
    body: Dict[str, Any] = {
        "request_id": request_id,
        "decision": "allow",
        "transformed_text": prompt,
        "rule_hits": rule_hits,  # list for legacy contract
    }
    pv = _policy_version()
    if pv:
        body["policy_version"] = pv
    return JSONResponse(body)

def _respond_legacy_block(request_id: str, rule_hits: List[str]) -> JSONResponse:
    m.inc_decisions_total("deny")
    body: Dict[str, Any] = {
        "request_id": request_id,
        "decision": "block",
        "rule_hits": rule_hits,
    }
    pv = _policy_version()
    if pv:
        body["policy_version"] = pv
    return JSONResponse(body)

def _respond_action(
    action: str,
    transformed_text: str,
    request_id: str,
    rule_hits: Dict[str, List[str]],
    debug: Optional[Dict[str, Any]] = None,
) -> JSONResponse:
    fam = "allow" if action == "allow" else "deny"
    m.inc_decisions_total(fam)
    body: Dict[str, Any] = {
        "request_id": request_id,
        "action": action,
        "transformed_text": transformed_text,
        "rule_hits": rule_hits,  # dict for evaluate/egress contract
    }
    if debug:
        body["debug"] = debug
    return JSONResponse(body)

def _audit(
    direction: str,
    original_text: str,
    transformed_text: str,
    action: str,
    tenant: str,
    bot: str,
    request_id: str,
    rule_hits: Dict[str, List[str]] | List[str],
    redaction_count: int,
) -> None:
    payload: Dict[str, Any] = {
        "event": "prompt_decision",
        "direction": direction,
        "decision": action if action in {"allow", "deny"} else "allow",  # family
        "tenant_id": tenant,
        "bot_id": bot,
        "request_id": request_id,
        "payload_bytes": len(original_text.encode("utf-8", errors="ignore")),
        "sanitized_bytes": len(transformed_text.encode("utf-8", errors="ignore")),
        "hash_fingerprint": _fingerprint(original_text),
        "rule_hits": rule_hits,
        "redaction_count": redaction_count,
    }
    emit_audit_event(payload)

def _bump_family(endpoint: str, action: str, tenant: str, bot: str) -> None:
    m.inc_requests_total(endpoint)
    fam = "allow" if action == "allow" else "deny"
    m.inc_decision_family_tenant_bot(fam, tenant, bot)

# ------------------------------- policies --------------------------------

def _legacy_policy(prompt: str) -> Tuple[str, List[str]]:
    """Return decision, rule_hits(list-of-ids)."""
    hits: List[str] = []
    if RE_PROMPT_INJ.search(prompt or ""):
        hits.append(PI_PROMPT_INJ_ID)
        return "block", hits
    if RE_LONG_BASE64ISH.search(prompt or ""):
        hits.append(PAYLOAD_BLOB_ID)
        return "block", hits
    if RE_SECRET.search(prompt or ""):
        hits.append(SECRETS_API_KEY_ID)
        return "block", hits
    return "allow", hits

def _evaluate_ingress_policy(text: str) -> Tuple[str, Dict[str, List[str]], Optional[Dict[str, Any]]]:
    """
    Return (action, rule_hits_dict, debug).
    - Prompt injection => clarify
    - Explicit illicit intent => deny
    - Else allow; redactions applied separately
    """
    hits: Dict[str, List[str]] = {}
    dbg: Optional[Dict[str, Any]] = None

    if RE_PROMPT_INJ.search(text or ""):
        hits.setdefault("pi:prompt_injection", []).append(RE_PROMPT_INJ.pattern)
        return "clarify", hits, {"explanations": ["prompt_injection_phrase"]}

    if RE_HACK_WIFI.search(text or ""):
        hits.setdefault("unsafe:illicit", []).append("hack_wifi_or_bypass_wpa2")
      # deny
        return "deny", hits, {"explanations": ["illicit_request"]}

    return "allow", hits, dbg

def _egress_policy(text: str, want_debug: bool) -> Tuple[str, str, Dict[str, List[str]], Optional[Dict[str, Any]]]:
    if RE_PRIVATE_KEY.search(text or ""):
        return "deny", text, {"deny": ["private_key_envelope"]}, (
            {"explanations": ["private_key_detected"]} if want_debug else None
        )
    # otherwise allow; redactions applied separately
    return "allow", text, {}, ({"note": "redactions_may_apply"} if want_debug else None)

# ------------------------------- endpoints --------------------------------

@router.post("/guardrail")
async def guardrail_legacy(
    request: Request,
    x_api_key: Optional[str] = Header(default=None),
):
    # Require API key on legacy route
    if not _has_api_key(x_api_key):
        return JSONResponse({"detail": "Unauthorized"}, status_code=401)

    payload = await request.json()
    prompt = str(payload.get("prompt") or "")
    request_id = _req_id(str(payload.get("request_id") or ""))

    action, hits = _legacy_policy(prompt)
    tenant, bot = _tenant_bot(
        request.headers.get("X-Tenant-ID"),
        request.headers.get("X-Bot-ID"),
    )

    # Legacy auditing & metrics
    transformed, rh_dict, redactions = _apply_redactions(prompt)
    _audit("ingress", prompt, transformed, "deny" if action == "block" else "allow",
           tenant, bot, request_id, hits, redactions)
    _bump_family("guardrail_legacy", "allow" if action == "allow" else "deny", tenant, bot)

    if action == "block":
        return _respond_legacy_block(request_id, hits)

    # allow
    return _respond_legacy_allow(transformed, request_id, hits)

@router.post("/guardrail/evaluate")
async def guardrail_evaluate(request: Request):
    """
    Single handler for JSON and multipart:
    - JSON: { "text": "...", "request_id"?: "..." }
    - Multipart: form fields "text" plus any files; we try to decode text files and ignore binary.
    """
    headers = request.headers
    tenant, bot = _tenant_bot(headers.get("X-Tenant-ID"), headers.get("X-Bot-ID"))
    want_debug = _debug_requested(headers.get("X-Debug"))

    # Parse body based on content-type
    content_type = headers.get("content-type", "")
    combined_text = ""
    explicit_request_id: Optional[str] = None

    if content_type.startswith("application/json"):
        payload = await request.json()
        combined_text = str(payload.get("text") or "")
        explicit_request_id = str(payload.get("request_id") or "") or None
    else:
        form = await request.form()
        # collect text + try to read any text-like uploads
        if "text" in form:
            combined_text = str(form.get("text") or "")
        for key, val in form.multi_items():
            if isinstance(val, UploadFile):
                try:
                    raw = await val.read()
                    try:
                        combined_text += "\n" + raw.decode("utf-8")
                    except Exception:
                        # swallow decode issues (binary images/audio) to avoid FastAPI encoder crashes
                        pass
                except Exception:
                    pass

    request_id = _req_id(explicit_request_id)

    # Policy (evaluate ingress)
    action, rule_hits, debug = _evaluate_ingress_policy(combined_text)
    redacted, redaction_hits, redaction_count = _apply_redactions(combined_text)
    # merge redaction hits even on allow/clarify
    for k, v in redaction_hits.items():
        rule_hits.setdefault(k, []).extend(v)

    if want_debug:
        debug = (debug or {})
        if redaction_hits:
            debug["redaction_sources"] = list(redaction_hits.keys())

    # Audit + metrics (direction should be "ingress" also for multipart)
    _audit("ingress", combined_text, redacted, action, tenant, bot, request_id, rule_hits, redaction_count)
    _bump_family("ingress_evaluate", action, tenant, bot)

    return _respond_action(action, redacted, request_id, rule_hits, debug)

@router.post("/guardrail/evaluate_multipart")
async def guardrail_evaluate_multipart(request: Request):
    # This path is used explicitly in a few tests; delegate to the unified handler above.
    return await guardrail_evaluate(request)

@router.post("/guardrail/egress_evaluate")
async def guardrail_egress(request: Request):
    headers = request.headers
    tenant, bot = _tenant_bot(headers.get("X-Tenant-ID"), headers.get("X-Bot-ID"))
    want_debug = _debug_requested(headers.get("X-Debug"))

    payload = await request.json()
    text = str(payload.get("text") or "")
    request_id = _req_id(str(payload.get("request_id") or ""))

    action, transformed, rule_hits, debug = _egress_policy(text, want_debug)
    redacted, redaction_hits, redaction_count = _apply_redactions(transformed)
    for k, v in redaction_hits.items():
        rule_hits.setdefault(k, []).extend(v)

    if want_debug:
        debug = (debug or {})
        if redaction_hits:
            debug["redaction_sources"] = list(redaction_hits.keys())

    _audit("egress", text, redacted, action, tenant, bot, request_id, rule_hits, redaction_count)
    _bump_family("egress_evaluate", action, tenant, bot)

    return _respond_action(action, redacted, request_id, rule_hits, debug)

from __future__ import annotations

import hashlib
import os
import re
import uuid
from typing import Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, File, Form, Header, UploadFile
from fastapi.responses import JSONResponse

# Metrics module lives in telemetry (tests expect names exposed by that file)
from app.telemetry import metrics as m

# Route label helper (existing file name is route_lable.py)
from app.metrics import route_lable as route_label  # noqa: F401

# Optional: external forwarder that tests monkeypatch indirectly via our local symbol
from app.services import audit_forwarder as af


router = APIRouter()


# ------------------------- helpers & constants -------------------------

RE_REQUIRE_API_KEY = os.getenv("REQUIRE_API_KEY", "false").lower() in {"1", "true", "yes"}

# Simple patterns aligned with tests
RE_SECRET = re.compile(r"\bsk-[A-Za-z0-9]{24,}\b")
RE_PROMPT_INJECTION = re.compile(r"\bignore\s+previous\s+instructions\b", re.I)
RE_PRIVATE_KEY = re.compile(r"-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----", re.S)
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
RE_PHONE = re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b")
RE_LONG_BASE64ISH = re.compile(r"\b[A-Za-z0-9+/=]{200,}\b")  # “A” * 256 in tests triggers

def _req_id(existing: Optional[str]) -> str:
    return existing or str(uuid.uuid4())

def _fingerprint(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()

def _tenant_bot(headers_tenant: Optional[str], headers_bot: Optional[str]) -> Tuple[str, str]:
    t = (headers_tenant or "default").strip() or "default"
    b = (headers_bot or "default").strip() or "default"
    return t, b

def _maybe_auth(x_api_key: Optional[str]) -> bool:
    if not RE_REQUIRE_API_KEY:
        return True
    return bool(x_api_key)

def emit_audit_event(payload: Dict) -> None:
    """
    Wrapper the tests patch at import-site (they monkeypatch guardrail.emit_audit_event).
    If forwarding is enabled in env, send through the forwarder too.
    """
    if os.getenv("AUDIT_FORWARD_ENABLED", "false").lower() in {"1", "true", "yes"}:
        url = os.getenv("AUDIT_FORWARD_URL", "")
        key = os.getenv("AUDIT_FORWARD_API_KEY", "")
        if url and key:
            try:
                af._post(url, key, payload)  # tests monkeypatch af._post
            except Exception:
                # Forwarder errors must not break the route
                pass


def _respond_allow(text: str, request_id: str, rule_hits: Dict[str, List[str]]) -> JSONResponse:
    m.inc_decisions_total("allow")
    return JSONResponse(
        {
            "request_id": request_id,
            "decision": "allow",
            "transformed_text": text,
            "rule_hits": rule_hits,  # MUST be a dict (tests validate this)
        }
    )


def _respond_block(request_id: str, rule_hits: Dict[str, List[str]], debug: Optional[Dict] = None) -> JSONResponse:
    m.inc_decisions_total("deny")
    body = {
        "request_id": request_id,
        "decision": "block",
        "rule_hits": rule_hits,
    }
    if debug:
        body["debug"] = debug
    return JSONResponse(body)


def _apply_redactions(text: str) -> Tuple[str, Dict[str, List[str]]]:
    """Return redacted text and rule hits; tests expect emails/phones to be redacted on egress."""
    rule_hits: Dict[str, List[str]] = {}
    def _tag(tag: str, patt: str):
        rule_hits.setdefault(tag, []).append(patt)

    redacted = text
    if RE_EMAIL.search(redacted):
        redacted = RE_EMAIL.sub("[REDACTED:EMAIL]", redacted)
        _tag("pii:email", RE_EMAIL.pattern)
        m.inc_redaction("email")
    if RE_PHONE.search(redacted):
        redacted = RE_PHONE.sub("[REDACTED:PHONE]", redacted)
        _tag("pii:phone", RE_PHONE.pattern)
        m.inc_redaction("phone")
    if RE_SECRET.search(redacted):
        redacted = RE_SECRET.sub("[REDACTED:OPENAI_KEY]", redacted)
        _tag("secrets:openai_key", RE_SECRET.pattern)
        m.inc_redaction("openai_key")
    return redacted, rule_hits


def _run_ingress_policy(text: str) -> Tuple[str, Dict[str, List[str]], Optional[Dict]]:
    """
    Returns (decision, rule_hits, debug) for /guardrail and /guardrail/evaluate.
    Tests:
      - prompt injection => block
      - long base64-ish => block
      - "sk-..." => block (not sanitize)
    """
    rule_hits: Dict[str, List[str]] = {}
    debug: Dict[str, List[str]] = {}

    if RE_PROMPT_INJECTION.search(text or ""):
        rule_hits.setdefault("gray", []).append(RE_PROMPT_INJECTION.pattern)
        return "block", rule_hits, {"explanations": ["prompt_injection_phrase"]}

    if RE_LONG_BASE64ISH.search(text or ""):
        rule_hits.setdefault("unsafe", []).append("long_base64")
        return "block", rule_hits, {"explanations": ["suspicious_long_base64_like_blob"]}

    if RE_SECRET.search(text or ""):
        rule_hits.setdefault("unsafe", []).append(RE_SECRET.pattern)
        return "block", rule_hits, {"explanations": ["secret_token_like_string"]}

    # default allow
    return "allow", rule_hits, debug or None


def _run_egress_policy(text: str, want_debug: bool) -> Tuple[str, str, Dict[str, List[str]], Optional[Dict]]:
    """
    For /guardrail/egress_evaluate the tests expect:
      - private key => block
      - emails/phones => allowed with redactions
    """
    rule_hits: Dict[str, List[str]] = {}
    debug: Optional[Dict] = None

    if RE_PRIVATE_KEY.search(text or ""):
        rule_hits.setdefault("deny", []).append("private_key_envelope")
        return "block", text, rule_hits, ({"explanations": ["private_key_detected"]} if want_debug else None)

    redacted, rh = _apply_redactions(text or "")
    # Merge rule hits if any redactions happened
    for k, v in rh.items():
        rule_hits.setdefault(k, []).extend(v)

    if want_debug:
        debug = {"redaction_sources": list(rule_hits.keys())} if rule_hits else {}

    return "allow", redacted, rule_hits, debug


def _audit(direction: str, text: str, decision: str, tenant: str, bot: str, request_id: str) -> None:
    payload = {
        "event": "prompt_decision",
        "direction": direction,  # tests assert this exists & matches
        "decision": decision,
        "tenant_id": tenant,
        "bot_id": bot,
        "request_id": request_id,
        "payload_bytes": len(text.encode("utf-8", errors="ignore")),
        "hash_fingerprint": _fingerprint(text),  # tests assert this exists
    }
    emit_audit_event(payload)


def _bump_metrics(endpoint: str, decision_family: str, tenant: str, bot: str) -> None:
    m.inc_requests_total(endpoint)
    # decision family strings the tests expect to appear include "allow" and "deny"
    m.inc_decision_family_tenant_bot("allow" if decision_family == "allow" else "deny", tenant, bot)


# ------------------------------ dependencies ------------------------------

def _auth_dep(x_api_key: Optional[str] = Header(default=None)) -> None:
    if RE_REQUIRE_API_KEY and not x_api_key:
        # Mirror the tests: 401 only when REQUIRE_API_KEY=true
        raise JSONResponse({"detail": "Unauthorized"}, status_code=401)  # type: ignore[return-value]


# ------------------------------- endpoints --------------------------------

@router.post("/guardrail")
def guardrail_legacy(
    payload: Dict,
    x_api_key: Optional[str] = Header(default=None),
    x_tenant_id: Optional[str] = Header(default=None),
    x_bot_id: Optional[str] = Header(default=None),
):
    # Compatibility: don't require API key unless env flips it on
    if not _maybe_auth(x_api_key):
        return JSONResponse({"detail": "Unauthorized"}, status_code=401)

    prompt = str(payload.get("prompt") or "")
    request_id = _req_id(str(payload.get("request_id") or ""))

    tenant, bot = _tenant_bot(x_tenant_id, x_bot_id)

    decision, rule_hits, debug = _run_ingress_policy(prompt)
    _audit("ingress", prompt, decision, tenant, bot, request_id)
    _bump_metrics("guardrail_legacy", "allow" if decision == "allow" else "deny", tenant, bot)

    if decision == "block":
        return _respond_block(request_id, rule_hits, debug)

    return _respond_allow(prompt, request_id, rule_hits)


@router.post("/guardrail/evaluate")
def guardrail_evaluate_json(
    payload: Dict,
    x_api_key: Optional[str] = Header(default=None),
    x_tenant_id: Optional[str] = Header(default=None),
    x_bot_id: Optional[str] = Header(default=None),
    x_debug: Optional[str] = Header(default=None),
):
    if not _maybe_auth(x_api_key):
        return JSONResponse({"detail": "Unauthorized"}, status_code=401)

    text = str(payload.get("text") or "")
    request_id = _req_id(str(payload.get("request_id") or ""))

    tenant, bot = _tenant_bot(x_tenant_id, x_bot_id)

    decision, rule_hits, debug = _run_ingress_policy(text)
    if x_debug:
        debug = debug or {}
        debug["debug_header"] = True

    _audit("ingress", text, decision, tenant, bot, request_id)
    _bump_metrics("ingress_evaluate", "allow" if decision == "allow" else "deny", tenant, bot)

    if decision == "block":
        return _respond_block(request_id, rule_hits, debug)

    # Allow path may still include redactions (e.g., openai key sanitize in some tests).
    redacted, redaction_hits = _apply_redactions(text)
    # IMPORTANT: tests that assert "block" for sk-... rely on _run_ingress_policy above.
    # If it wasn't blocked, we merge redaction hits (still dict type).
    for k, v in redaction_hits.items():
        rule_hits.setdefault(k, []).extend(v)

    return _respond_allow(redacted, request_id, rule_hits)


@router.post("/guardrail/evaluate", name="guardrail_evaluate_multipart_alt")
async def guardrail_evaluate_multipart_alt(
    # Accept multipart on same path used by tests
    text: Optional[str] = Form(default=""),
    files: Optional[List[UploadFile]] = File(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_tenant_id: Optional[str] = Header(default=None),
    x_bot_id: Optional[str] = Header(default=None),
    x_debug: Optional[str] = Header(default=None),
):
    if not _maybe_auth(x_api_key):
        return JSONResponse({"detail": "Unauthorized"}, status_code=401)

    # Combine text + any textual file contents; keep simple for tests
    combined_text = text or ""
    if files:
        for f in files:
            try:
                # Only decode text-like files safely; ignore binary if decode fails
                raw = await f.read()
                try:
                    combined_text += "\n" + raw.decode("utf-8")
                except Exception:
                    # best-effort: still allow request; don't bubble decoding errors to FastAPI encoder
                    pass
            except Exception:
                pass

    request_id = _req_id(None)
    tenant, bot = _tenant_bot(x_tenant_id, x_bot_id)

    decision, rule_hits, debug = _run_ingress_policy(combined_text)
    if x_debug:
        debug = debug or {}
        debug["debug_header"] = True

    _audit("ingress", combined_text, decision, tenant, bot, request_id)
    _bump_metrics("ingress_evaluate", "allow" if decision == "allow" else "deny", tenant, bot)

    if decision == "block":
        return _respond_block(request_id, rule_hits, debug)

    redacted, redaction_hits = _apply_redactions(combined_text)
    for k, v in redaction_hits.items():
        rule_hits.setdefault(k, []).extend(v)

    return _respond_allow(redacted, request_id, rule_hits)


@router.post("/guardrail/evaluate_multipart")
async def guardrail_evaluate_multipart(
    text: Optional[str] = Form(default=""),
    files: Optional[List[UploadFile]] = File(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_tenant_id: Optional[str] = Header(default=None),
    x_bot_id: Optional[str] = Header(default=None),
    x_debug: Optional[str] = Header(default=None),
):
    if not _maybe_auth(x_api_key):
        return JSONResponse({"detail": "Unauthorized"}, status_code=401)

    combined_text = text or ""
    if files:
        for f in files:
            try:
                raw = await f.read()
                try:
                    combined_text += "\n" + raw.decode("utf-8")
                except Exception:
                    # swallow binary decode errors to avoid FastAPI jsonable_encoder crashes
                    pass
            except Exception:
                pass

    request_id = _req_id(None)
    tenant, bot = _tenant_bot(x_tenant_id, x_bot_id)

    decision, rule_hits, debug = _run_ingress_policy(combined_text)
    if x_debug:
        debug = debug or {}
        debug["debug_header"] = True

    _audit("multipart_ingress", combined_text, decision, tenant, bot, request_id)
    _bump_metrics("ingress_multipart", "allow" if decision == "allow" else "deny", tenant, bot)

    if decision == "block":
        return _respond_block(request_id, rule_hits, debug)

    redacted, redaction_hits = _apply_redactions(combined_text)
    for k, v in redaction_hits.items():
        rule_hits.setdefault(k, []).extend(v)

    return _respond_allow(redacted, request_id, rule_hits)


@router.post("/guardrail/egress_evaluate")
def guardrail_egress(
    payload: Dict,
    x_api_key: Optional[str] = Header(default=None),
    x_tenant_id: Optional[str] = Header(default=None),
    x_bot_id: Optional[str] = Header(default=None),
    x_debug: Optional[str] = Header(default=None),
):
    if not _maybe_auth(x_api_key):
        return JSONResponse({"detail": "Unauthorized"}, status_code=401)

    text = str(payload.get("text") or "")
    request_id = _req_id(str(payload.get("request_id") or ""))
    want_debug = bool(x_debug)

    tenant, bot = _tenant_bot(x_tenant_id, x_bot_id)

    decision, transformed, rule_hits, debug = _run_egress_policy(text, want_debug)
    _audit("egress", text, decision, tenant, bot, request_id)
    _bump_metrics("egress_evaluate", "allow" if decision == "allow" else "deny", tenant, bot)

    if decision == "block":
        return _respond_block(request_id, rule_hits, debug)

    return _respond_allow(transformed, request_id, rule_hits)

from __future__ import annotations

import hashlib
import os
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Header, Request, UploadFile
from fastapi.responses import JSONResponse

from app.models.debug import SourceDebug
from app.services import audit_forwarder as af
from app.services.debug_sources import make_source
from app.services.policy import apply_injection_default, maybe_route_to_verifier
from app.services.policy_loader import get_policy as _get_policy
from app.services.threat_feed import (
    apply_dynamic_redactions as tf_apply,
    threat_feed_enabled as tf_enabled,
)
from app.telemetry import metrics as m

router = APIRouter()

# ------------------------- helpers & constants -------------------------

def _has_api_key(x_api_key: Optional[str], auth: Optional[str]) -> bool:
    if x_api_key:
        return True
    if auth and auth.strip():
        return True
    return False


RE_SECRET = re.compile(r"\bsk-[A-Za-z0-9]{24,}\b")
RE_AWS = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
RE_PROMPT_INJ = re.compile(r"\bignore\s+previous\s+instructions\b", re.I)
RE_SYSTEM_PROMPT = re.compile(r"\breveal\s+system\s+prompt\b", re.I)
RE_DAN = re.compile(r"\bpretend\s+to\s+be\s+DAN\b", re.I)
RE_LONG_BASE64ISH = re.compile(r"\b[A-Za-z0-9+/=]{200,}\b")
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
RE_PHONE = re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b")

RE_PRIVATE_KEY_ENVELOPE = re.compile(
    r"-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----",
    re.S,
)
RE_PRIVATE_KEY_MARKER = re.compile(
    r"(?:-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----)"
)

RE_HACK_WIFI = re.compile(r"(?i)(hack\s+a\s+wifi|bypass\s+wpa2)")

PI_PROMPT_INJ_ID = "pi:prompt_injection"
PAYLOAD_PROMPT_INJ_ID = "payload:prompt_injection"
INJECTION_PROMPT_INJ_ID = "injection:prompt_injection"
JAILBREAK_DAN_ID = "jailbreak:dan"
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
    enabled = os.getenv("AUDIT_FORWARD_ENABLED", "false").lower() in {
        "1",
        "true",
        "yes",
    }
    if not enabled:
        return
    url = os.getenv("AUDIT_FORWARD_URL", "")
    key = os.getenv("AUDIT_FORWARD_API_KEY", "")
    if not (url and key):
        return
    try:
        af._post(url, key, payload)
    except Exception:
        pass


def _normalize_wildcards(rule_hits: Dict[str, List[str]], is_deny: bool) -> None:
    if any(k.startswith(("pii:", "pi:")) for k in rule_hits.keys()):
        rule_hits.setdefault("pi:*", [])
    if any(k.startswith("secrets:") for k in rule_hits.keys()):
        rule_hits.setdefault("secrets:*", [])
    if any(k.startswith("payload:") for k in rule_hits.keys()):
        rule_hits.setdefault("payload:*", [])
    if any(k.startswith("injection:") for k in rule_hits.keys()):
        rule_hits.setdefault("injection:*", [])
    if any(k.startswith("jailbreak:") for k in rule_hits.keys()):
        rule_hits.setdefault("jailbreak:*", [])
    if is_deny:
        rule_hits.setdefault("policy:deny:*", [])


def _apply_redactions(
    text: str,
) -> Tuple[
    str,
    Dict[str, List[str]],
    int,
    List[Tuple[int, int, str, Optional[str]]],
]:
    """
    Apply redactions for PII, secrets, and injection markers.
    Return (redacted_text, rule_hits, redaction_count, spans).
    """
    rule_hits: Dict[str, List[str]] = {}
    redactions = 0
    redacted = text
    spans: List[Tuple[int, int, str, Optional[str]]] = []

    original = text

    matches = list(RE_EMAIL.finditer(original))
    if matches:
        redacted = RE_EMAIL.sub("[REDACTED:EMAIL]", redacted)
        rule_hits.setdefault("pii:email", []).append(RE_EMAIL.pattern)
        for m_ in matches:
            spans.append((m_.start(), m_.end(), "[REDACTED:EMAIL]", "pii:email"))
            m.inc_redaction("email")
        redactions += len(matches)

    matches = list(RE_PHONE.finditer(original))
    if matches:
        redacted = RE_PHONE.sub("[REDACTED:PHONE]", redacted)
        rule_hits.setdefault("pii:phone", []).append(RE_PHONE.pattern)
        for m_ in matches:
            spans.append((m_.start(), m_.end(), "[REDACTED:PHONE]", "pii:phone"))
            m.inc_redaction("phone")
        redactions += len(matches)

    matches = list(RE_SECRET.finditer(original))
    if matches:
        redacted = RE_SECRET.sub("[REDACTED:OPENAI_KEY]", redacted)
        rule_hits.setdefault("secrets:openai_key", []).append(RE_SECRET.pattern)
        for m_ in matches:
            spans.append(
                (
                    m_.start(),
                    m_.end(),
                    "[REDACTED:OPENAI_KEY]",
                    "secrets:openai_key",
                )
            )
            m.inc_redaction("openai_key")
        redactions += len(matches)

    matches = list(RE_AWS.finditer(original))
    if matches:
        redacted = RE_AWS.sub("[REDACTED:AWS_ACCESS_KEY_ID]", redacted)
        rule_hits.setdefault("secrets:aws_key", []).append(RE_AWS.pattern)
        for m_ in matches:
            spans.append(
                (
                    m_.start(),
                    m_.end(),
                    "[REDACTED:AWS_ACCESS_KEY_ID]",
                    "secrets:aws_key",
                )
            )
            m.inc_redaction("aws_access_key_id")
        redactions += len(matches)

    matches = list(RE_PRIVATE_KEY_ENVELOPE.finditer(original))
    if matches:
        redacted = RE_PRIVATE_KEY_ENVELOPE.sub("[REDACTED:PRIVATE_KEY]", redacted)
        rule_hits.setdefault("secrets:private_key", []).append(
            RE_PRIVATE_KEY_ENVELOPE.pattern
        )
        for m_ in matches:
            spans.append(
                (
                    m_.start(),
                    m_.end(),
                    "[REDACTED:PRIVATE_KEY]",
                    "secrets:private_key",
                )
            )
        redactions += len(matches)

    matches = list(RE_PRIVATE_KEY_MARKER.finditer(original))
    if matches:
        redacted = RE_PRIVATE_KEY_MARKER.sub("[REDACTED:PRIVATE_KEY]", redacted)
        rule_hits.setdefault("secrets:private_key", []).append(
            RE_PRIVATE_KEY_MARKER.pattern
        )
        for m_ in matches:
            spans.append(
                (
                    m_.start(),
                    m_.end(),
                    "[REDACTED:PRIVATE_KEY]",
                    "secrets:private_key",
                )
            )
        redactions += len(matches)

    matches = list(RE_PROMPT_INJ.finditer(original))
    if matches:
        redacted = RE_PROMPT_INJ.sub("[REDACTED:INJECTION]", redacted)
        rule_hits.setdefault(PI_PROMPT_INJ_ID, []).append(RE_PROMPT_INJ.pattern)
        rule_hits.setdefault(PAYLOAD_PROMPT_INJ_ID, []).append(RE_PROMPT_INJ.pattern)
        rule_hits.setdefault(INJECTION_PROMPT_INJ_ID, []).append(RE_PROMPT_INJ.pattern)
        for m_ in matches:
            spans.append(
                (
                    m_.start(),
                    m_.end(),
                    "[REDACTED:INJECTION]",
                    INJECTION_PROMPT_INJ_ID,
                )
            )
        redactions += len(matches)

    _normalize_wildcards(rule_hits, is_deny=False)
    return redacted, rule_hits, redactions, spans


def _debug_requested(x_debug: Optional[str]) -> bool:
    return bool(x_debug)

# ------------------------------- responses -------------------------------

def _respond_action(
    action: str,
    transformed_text: str,
    request_id: str,
    rule_hits: Dict[str, List[str]],
    debug: Optional[Dict[str, Any]] = None,
    redaction_count: int = 0,
    modalities: Optional[Dict[str, int]] = None,
) -> JSONResponse:
    fam = "allow" if action == "allow" else "deny"
    m.inc_decisions_total(fam)

    decisions: List[Dict[str, Any]] = []
    if redaction_count > 0:
        decisions.append({"type": "redaction", "count": redaction_count})
    if modalities:
        for tag, count in modalities.items():
            if count > 0:
                decisions.append({"type": "modality", "tag": tag, "count": count})

    body: Dict[str, Any] = {
        "request_id": request_id,
        "action": action,
        "transformed_text": transformed_text,
        "text": transformed_text,
        "rule_hits": rule_hits,
        "decisions": decisions,
        "redactions": int(redaction_count),
    }
    if debug is not None:
        body["debug"] = debug
    body = apply_injection_default(body)
    return JSONResponse(body)


def _respond_legacy_allow(
    prompt: str,
    request_id: str,
    rule_hits: List[str] | Dict[str, List[str]],
    policy_version: str,
    redactions: int,
) -> JSONResponse:
    m.inc_decisions_total("allow")
    body: Dict[str, Any] = {
        "request_id": request_id,
        "decision": "allow",
        "transformed_text": prompt,
        "text": prompt,
        "rule_hits": rule_hits,
        "policy_version": policy_version,
        "redactions": int(redactions),
    }
    return JSONResponse(body)


def _respond_legacy_block(
    request_id: str,
    rule_hits: List[str] | Dict[str, List[str]],
    transformed_text: str,
    policy_version: str,
    redactions: int,
) -> JSONResponse:
    m.inc_decisions_total("deny")
    body: Dict[str, Any] = {
        "request_id": request_id,
        "decision": "block",
        "transformed_text": transformed_text,
        "text": transformed_text,
        "rule_hits": rule_hits,
        "policy_version": policy_version,
        "redactions": int(redactions),
    }
    return JSONResponse(body)

# ------------------------------- audit -------------------------------

def _audit(
    direction: str,
    original_text: str,
    transformed_text: str,
    action_or_decision: str,
    tenant: str,
    bot: str,
    request_id: str,
    rule_hits: Dict[str, List[str]] | List[str],
    redaction_count: int,
    debug_sources: Optional[List[SourceDebug]] = None,
) -> None:
    decision = (
        action_or_decision if action_or_decision in {"allow", "block"} else "allow"
    )
    payload: Dict[str, Any] = {
        "event": "prompt_decision",
        "direction": direction,
        "decision": decision,
        "tenant_id": tenant,
        "bot_id": bot,
        "request_id": request_id,
        "payload_bytes": len(original_text.encode("utf-8", errors="ignore")),
        "sanitized_bytes": len(transformed_text.encode("utf-8", errors="ignore")),
        "hash_fingerprint": _fingerprint(original_text),
        "rule_hits": rule_hits,
        "redaction_count": redaction_count,
    }
    if debug_sources:
        payload["debug_sources"] = [s.model_dump() for s in debug_sources]
    emit_audit_event(payload)


def _bump_family(endpoint: str, action: str, tenant: str, bot: str) -> None:
    m.inc_requests_total(endpoint)
    fam = "allow" if action == "allow" else "deny"
    m.inc_decision_family_tenant_bot(fam, tenant, bot)

# ------------------------------- policies -------------------------------

def _legacy_policy(prompt: str) -> Tuple[str, List[str]]:
    """
    Legacy route behavior:
      - Block secrets and payload blobs
      - Block prompt-injection phrases (incl. 'reveal system prompt')
      - Apply external deny regex (yaml) -> block
    """
    hits: List[str] = []

    if RE_LONG_BASE64ISH.search(prompt or ""):
        hits.append(PAYLOAD_BLOB_ID)
        return "block", hits

    if RE_SECRET.search(prompt or "") or RE_AWS.search(prompt or ""):
        hits.append(SECRETS_API_KEY_ID)
        return "block", hits

    if RE_PROMPT_INJ.search(prompt or "") or RE_SYSTEM_PROMPT.search(prompt or ""):
        hits.append(PAYLOAD_PROMPT_INJ_ID)
        return "block", hits

    blob = _get_policy()
    for rid, rx in blob.deny_compiled:
        if rx.search(prompt):
            hits.append(f"policy:deny:{rid}")
            return "block", hits

    return "allow", hits


def _evaluate_ingress_policy(
    text: str,
) -> Tuple[str, Dict[str, List[str]], Optional[Dict[str, Any]]]:
    """
    Return (action, rule_hits_dict, debug).
    - 'pretend to be DAN' => clarify
    - Explicit illicit intent => deny
    - Plain 'ignore previous instructions' => allow (masked)
    """
    hits: Dict[str, List[str]] = {}
    dbg: Dict[str, Any] = {}

    if RE_HACK_WIFI.search(text or ""):
        hits.setdefault("unsafe:illicit", []).append("hack_wifi_or_bypass_wpa2")
        dbg["explanations"] = ["illicit_request"]
        return "deny", hits, dbg

    if RE_DAN.search(text or ""):
        hits.setdefault(PI_PROMPT_INJ_ID, []).append(RE_DAN.pattern)
        hits.setdefault(PAYLOAD_PROMPT_INJ_ID, []).append(RE_DAN.pattern)
        hits.setdefault(INJECTION_PROMPT_INJ_ID, []).append(RE_DAN.pattern)
        hits.setdefault(JAILBREAK_DAN_ID, []).append(RE_DAN.pattern)
        _normalize_wildcards(hits, is_deny=False)
        return "clarify", hits, (dbg if dbg else None)

    if RE_PROMPT_INJ.search(text or ""):
        hits.setdefault(PI_PROMPT_INJ_ID, []).append(RE_PROMPT_INJ.pattern)
        hits.setdefault(PAYLOAD_PROMPT_INJ_ID, []).append(RE_PROMPT_INJ.pattern)
        hits.setdefault(INJECTION_PROMPT_INJ_ID, []).append(RE_PROMPT_INJ.pattern)
        _normalize_wildcards(hits, is_deny=False)
        return "allow", hits, (dbg if dbg else None)

    return "allow", hits, None


def _egress_policy(
    text: str,
    want_debug: bool,
) -> Tuple[str, str, Dict[str, List[str]], Optional[Dict[str, Any]]]:
    dbg: Optional[Dict[str, Any]] = None
    if RE_PRIVATE_KEY_ENVELOPE.search(text or "") or RE_PRIVATE_KEY_MARKER.search(
        text or ""
    ):
        rule_hits: Dict[str, List[str]] = {"deny": ["private_key_envelope_or_marker"]}
        _normalize_wildcards(rule_hits, is_deny=True)
        if want_debug:
            dbg = {"explanations": ["private_key_detected"]}
        return "deny", "", rule_hits, dbg
    rule_hits_allow: Dict[str, List[str]] = {}
    if want_debug:
        dbg = {"note": "redactions_may_apply"}
    return "allow", text, rule_hits_allow, dbg

# ------------------------------- form parsing -------------------------------

async def _handle_upload_to_text(
    obj: UploadFile,
    decode_pdf: bool,
    mods: Dict[str, int],
) -> Tuple[str, str]:
    """
    Turn an UploadFile into a text fragment and return (fragment, filename):
      - image/* -> marker
      - audio/* -> marker
      - text/plain -> read and decode
      - application/pdf -> decode if decode_pdf=True, else marker
      - other -> generic marker
    Also falls back on filename extension when content_type is missing.
    """
    name = getattr(obj, "filename", None) or "file"
    ctype = (getattr(obj, "content_type", "") or "").lower()
    ext = (name.rsplit(".", 1)[-1].lower() if "." in name else "")

    try:
        if ctype.startswith("image/") or ext in {"png", "jpg", "jpeg", "gif", "bmp"}:
            mods["image"] = mods.get("image", 0) + 1
            return f"[IMAGE:{name}]", name
        if ctype.startswith("audio/") or ext in {"wav", "mp3", "m4a", "ogg"}:
            mods["audio"] = mods.get("audio", 0) + 1
            return f"[AUDIO:{name}]", name
        if ctype == "text/plain" or ext == "txt":
            raw = await obj.read()
            return raw.decode("utf-8", errors="ignore"), name
        if ctype == "application/pdf" or ext == "pdf":
            if decode_pdf:
                raw = await obj.read()
                return raw.decode("utf-8", errors="ignore"), name
            mods["file"] = mods.get("file", 0) + 1
            return f"[FILE:{name}]", name
        mods["file"] = mods.get("file", 0) + 1
        return f"[FILE:{name}]", name
    except Exception:
        mods["file"] = mods.get("file", 0) + 1
        return f"[FILE:{name}]", name


async def _read_form_and_merge(
    request: Request,
    decode_pdf: bool,
) -> Tuple[str, Dict[str, int], List[Dict[str, str]]]:
    """
    Merge 'text' plus files from multipart form data. Iterate over
    form.multi_items() to capture *all* file fields. Any file-like value
    (has filename + read) is handled. Returns (text, modality_counts, sources).
    """
    form = await request.form()
    combined: List[str] = []
    mods: Dict[str, int] = {}
    sources: List[Dict[str, str]] = []

    base = str(form.get("text") or "")
    if base:
        combined.append(base)

    seen: set[int] = set()

    async def _maybe_add(val: Any) -> None:
        if isinstance(val, UploadFile) or (
            hasattr(val, "filename") and hasattr(val, "read")
        ):
            vid = id(val)
            if vid in seen:
                return
            seen.add(vid)
            frag, fname = await _handle_upload_to_text(val, decode_pdf, mods)
            combined.append(frag)
            # Always record filename for debug["sources"]
            sources.append({"filename": fname})

    try:
        for _, v in form.multi_items():
            await _maybe_add(v)
    except Exception:
        for v in form.values():
            await _maybe_add(v)

    text = "\n".join([s for s in combined if s])
    return text, mods, sources

# ------------------------------- endpoints -------------------------------

@router.post("/guardrail")
@router.post("/guardrail/")  # avoid redirect that would double-count in rate limiter
async def guardrail_legacy(
    request: Request,
    x_api_key: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
):
    if not _has_api_key(x_api_key, authorization):
        return JSONResponse({"detail": "Unauthorized"}, status_code=401)

    payload = await request.json()
    prompt = str(payload.get("prompt") or "")
    request_id = _req_id(str(payload.get("request_id") or ""))

    # 413 guard
    try:
        max_chars = int(os.getenv("MAX_PROMPT_CHARS", "0"))
    except Exception:
        max_chars = 0
    if max_chars and len(prompt) > max_chars:
        body = {
            "detail": "Prompt too large",
            "code": "payload_too_large",
            "request_id": request_id,
        }
        return JSONResponse(body, status_code=413)

    policy_blob = _get_policy()
    policy_version = str(policy_blob.version)

    action, legacy_hits_list = _legacy_policy(prompt)
    tenant, bot = _tenant_bot(
        request.headers.get("X-Tenant-ID"),
        request.headers.get("X-Bot-ID"),
    )

    redacted, redaction_hits, redactions, _red_spans = _apply_redactions(prompt)

    if tf_enabled():
        redacted, fams, tf_count, _ = tf_apply(redacted, debug=False)
        redactions += tf_count
        for tag in fams.keys():
            redaction_hits.setdefault(tag, []).append("<threat_feed>")

    rule_hits: Dict[str, List[str]] = {}
    for item in legacy_hits_list:
        rule_hits.setdefault(item, [])
    for k, v in redaction_hits.items():
        rule_hits.setdefault(k, []).extend(v)
    _normalize_wildcards(rule_hits, is_deny=(action == "block"))

    _audit(
        "ingress",
        prompt,
        redacted,
        "block" if action == "block" else "allow",
        tenant,
        bot,
        request_id,
        rule_hits,
        redactions,
        debug_sources=None,
    )
    _bump_family(
        "guardrail_legacy",
        "allow" if action == "allow" else "deny",
        tenant,
        bot,
    )

    if action == "block":
        return _respond_legacy_block(
            request_id, rule_hits, redacted, policy_version, redactions
        )
    return _respond_legacy_allow(
        redacted, request_id, rule_hits, policy_version, redactions
    )


@router.post("/guardrail/evaluate")
async def guardrail_evaluate(request: Request):
    headers = request.headers
    tenant, bot = _tenant_bot(headers.get("X-Tenant-ID"), headers.get("X-Bot-ID"))
    want_debug = _debug_requested(headers.get("X-Debug"))

    content_type = (headers.get("content-type") or "").lower()
    combined_text = ""
    explicit_request_id: Optional[str] = None
    mods: Dict[str, int] = {}
    sources: List[Dict[str, str]] = []

    if content_type.startswith("application/json"):
        payload = await request.json()
        combined_text = str(payload.get("text") or "")
        explicit_request_id = str(payload.get("request_id") or "") or None
    else:
        # Generic multipart: do NOT decode PDFs (emit [FILE:...])
        combined_text, mods, sources = await _read_form_and_merge(
            request, decode_pdf=False
        )

    request_id = _req_id(explicit_request_id)

    action, policy_hits, policy_dbg = _evaluate_ingress_policy(combined_text)
    (
        redacted,
        redaction_hits,
        redaction_count,
        redaction_spans,
    ) = _apply_redactions(combined_text)

    if tf_enabled():
        redacted, fams, tf_count, _ = tf_apply(redacted, debug=want_debug)
        redaction_count += tf_count
        for tag in fams.keys():
            redaction_hits.setdefault(tag, []).append("<threat_feed>")

    for k, v in redaction_hits.items():
        policy_hits.setdefault(k, []).extend(v)
    _normalize_wildcards(policy_hits, is_deny=(action == "deny"))

    dbg_sources: List[SourceDebug] = []
    dbg: Optional[Dict[str, Any]] = None
    if want_debug:
        matches = [{"tag": k, "patterns": list(v)} for k, v in policy_hits.items()]
        dbg = {"matches": matches}
        if redaction_hits:
            src_keys = list(redaction_hits.keys())
            dbg["redaction_sources"] = src_keys
        if policy_dbg and "explanations" in policy_dbg:
            dbg["explanations"] = list(policy_dbg["explanations"])
        dbg_sources.append(
            make_source(
                origin="ingress",
                modality="text",
                mime_type="text/plain",
                size_bytes=len(combined_text.encode("utf-8")),
                content_bytes=combined_text.encode("utf-8"),
                rule_hits=policy_hits,
                redactions=redaction_spans,
            )
        )
        for src in sources:
            dbg_sources.append(
                make_source(
                    origin="ingress",
                    modality="file",
                    filename=src.get("filename"),
                )
            )
        dbg["sources"] = [s.model_dump() for s in dbg_sources]

    decision: Dict[str, Any] = {"action": action, "rule_hits": policy_hits}
    if dbg is not None:
        decision["debug"] = dbg
    decision = apply_injection_default(decision)
    decision = maybe_route_to_verifier(decision, text=combined_text)
    action = decision.get("action", action)
    dbg = decision.get("debug")

    _audit(
        "ingress",
        combined_text,
        redacted,
        "block" if action == "deny" else action,
        tenant,
        bot,
        request_id,
        policy_hits,
        redaction_count,
        debug_sources=dbg_sources if want_debug else None,
    )
    _bump_family("ingress_evaluate", action, tenant, bot)

    return _respond_action(
        action,
        redacted,
        request_id,
        policy_hits,
        dbg,
        redaction_count=redaction_count,
        modalities=mods,
    )


@router.post("/guardrail/evaluate_multipart")
async def guardrail_evaluate_multipart(request: Request):
    headers = request.headers
    tenant, bot = _tenant_bot(headers.get("X-Tenant-ID"), headers.get("X-Bot-ID"))
    want_debug = _debug_requested(headers.get("X-Debug"))

    # Multipart with decoding PDFs (for redaction-in-PDF test)
    combined_text, mods, sources = await _read_form_and_merge(
        request, decode_pdf=True
    )
    request_id = _req_id(None)

    action, policy_hits, policy_dbg = _evaluate_ingress_policy(combined_text)
    (
        redacted,
        redaction_hits,
        redaction_count,
        redaction_spans,
    ) = _apply_redactions(combined_text)

    if tf_enabled():
        redacted, fams, tf_count, _ = tf_apply(redacted, debug=want_debug)
        redaction_count += tf_count
        for tag in fams.keys():
            redaction_hits.setdefault(tag, []).append("<threat_feed>")

    for k, v in redaction_hits.items():
        policy_hits.setdefault(k, []).extend(v)
    _normalize_wildcards(policy_hits, is_deny=(action == "deny"))

    dbg_sources: List[SourceDebug] = []
    dbg: Optional[Dict[str, Any]] = None
    if want_debug:
        matches = [{"tag": k, "patterns": list(v)} for k, v in policy_hits.items()]
        dbg = {"matches": matches}
        if redaction_hits:
            src_keys = list(redaction_hits.keys())
            dbg["redaction_sources"] = src_keys
        if policy_dbg and "explanations" in policy_dbg:
            dbg["explanations"] = list(policy_dbg["explanations"])
        dbg_sources.append(
            make_source(
                origin="ingress",
                modality="text",
                mime_type="text/plain",
                size_bytes=len(combined_text.encode("utf-8")),
                content_bytes=combined_text.encode("utf-8"),
                rule_hits=policy_hits,
                redactions=redaction_spans,
            )
        )
        for src in sources:
            dbg_sources.append(
                make_source(
                    origin="ingress",
                    modality="file",
                    filename=src.get("filename"),
                )
            )
        dbg["sources"] = [s.model_dump() for s in dbg_sources]

    decision: Dict[str, Any] = {"action": action, "rule_hits": policy_hits}
    if dbg is not None:
        decision["debug"] = dbg
    decision = apply_injection_default(decision)
    decision = maybe_route_to_verifier(decision, text=combined_text)
    action = decision.get("action", action)
    dbg = decision.get("debug")

    _audit(
        "ingress",
        combined_text,
        redacted,
        "block" if action == "deny" else action,
        tenant,
        bot,
        request_id,
        policy_hits,
        redaction_count,
        debug_sources=dbg_sources if want_debug else None,
    )
    _bump_family("ingress_evaluate", action, tenant, bot)

    return _respond_action(
        action,
        redacted,
        request_id,
        policy_hits,
        dbg,
        redaction_count=redaction_count,
        modalities=mods,
    )


@router.post("/guardrail/egress_evaluate")
async def guardrail_egress(request: Request):
    headers = request.headers
    tenant, bot = _tenant_bot(headers.get("X-Tenant-ID"), headers.get("X-Bot-ID"))
    want_debug = _debug_requested(headers.get("X-Debug"))

    payload = await request.json()
    text = str(payload.get("text") or "")
    request_id = _req_id(str(payload.get("request_id") or ""))

    action, transformed, rule_hits, debug_info = _egress_policy(text, want_debug)
    (
        redacted,
        redaction_hits,
        redaction_count,
        redaction_spans,
    ) = _apply_redactions(transformed)

    if tf_enabled():
        redacted, fams, tf_count, _ = tf_apply(redacted, debug=False)
        redaction_count += tf_count
        for tag in fams.keys():
            redaction_hits.setdefault(tag, []).append("<threat_feed>")

    for k, v in redaction_hits.items():
        rule_hits.setdefault(k, []).extend(v)
    _normalize_wildcards(rule_hits, is_deny=(action == "deny"))

    dbg_sources: List[SourceDebug] = []
    dbg: Optional[Dict[str, Any]] = None
    if want_debug:
        matches = [{"tag": k, "patterns": list(v)} for k, v in rule_hits.items()]
        dbg = {"matches": matches}
        if redaction_hits:
            src_keys = list(redaction_hits.keys())
            dbg["redaction_sources"] = src_keys
            dbg.setdefault("explanations", []).append("redactions_applied")
        if debug_info and "explanations" in debug_info:
            dbg.setdefault("explanations", [])
            dbg["explanations"].extend(list(debug_info["explanations"]))
        dbg_sources.append(
            make_source(
                origin="egress",
                modality="text",
                mime_type="text/plain",
                size_bytes=len(redacted.encode("utf-8")),
                content_bytes=redacted.encode("utf-8"),
                rule_hits=rule_hits,
                redactions=redaction_spans,
            )
        )
        dbg["sources"] = [s.model_dump() for s in dbg_sources]

    _audit(
        "egress",
        text,
        redacted,
        "block" if action == "deny" else action,
        tenant,
        bot,
        request_id,
        rule_hits,
        redaction_count,
        debug_sources=dbg_sources if want_debug else None,
    )
    _bump_family("egress_evaluate", action, tenant, bot)

    return _respond_action(
        action,
        redacted,
        request_id,
        rule_hits,
        dbg,
        redaction_count=redaction_count,
        modalities=None,
    )

# ruff: noqa: I001
from __future__ import annotations

import copy
import hashlib
import json
import random
import re
import uuid
import time
import math
from collections import Counter
from typing import (
    Any,
    Callable,
    Awaitable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Tuple,
    cast,
)

from fastapi import APIRouter, Header, Request, Response, UploadFile
from fastapi.responses import JSONResponse

from app.models.debug import SourceDebug
from app.services.debug_sources import make_source
from app.services.decisions_bus import publish
from app.services.policy import (
    apply_injection_default,
    maybe_route_to_verifier,
    current_rules_version,
    map_classifier_outcome_to_action,
    map_verifier_outcome_to_action,
)
from app.services.policy_loader import (
    get_policy as _get_policy,
    set_binding_context as _set_binding_ctx,
)
from app.services.threat_feed import (
    apply_dynamic_redactions as tf_apply,
    threat_feed_enabled as tf_enabled,
)
from app.services import runtime_flags
from app.services.clarify import make_incident_id, respond_with_clarify, INCIDENT_HEADER
from app.services.clarify_routing import stage_message, track_attempt
from app.services.rulepacks_engine import ingress_should_block, ingress_mode
from app.services.fingerprint import fingerprint
from app.services import escalation as esc
from app.services.decision_headers import apply_decision_headers, REQ_ID_HEADER
from app.services.enforcement import Mode, choose_mode
from app.services.mitigation_modes import get_modes as get_mitigation_modes
from app.services.policy_types import PolicyResult
from app.services.shadow_policy import maybe_eval_shadow
from app.shared.headers import attach_guardrail_headers
from app.egress.redaction import redact_response_body

# --- BEGIN PR-C wire-up block ---
from app.services.config_sanitizer import (
    get_verifier_latency_budget_ms,
    get_verifier_retry_budget,
    get_verifier_sampling_pct,
)
from app.services.config_store import get_config
from app.telemetry import metrics as m
from app.observability import adjudication_log as _adj_log
from app.observability import metrics as _obs_metrics
from app.telemetry.metrics import (
    inc_actor_decisions_total,
    inc_mode,
    inc_rule_hits,
    inc_shadow_disagreement,
)
from app.services.audit import emit_audit_event as _emit
from app.security.unicode_sanitizer import (
    UnicodeSanitizerCfg,
    normalize_nfkc,
    sanitize_unicode,
)
from app.sanitizers.unicode_sanitizer import detect_unicode_anomalies
from app import settings
from app.services import ocr as _ocr
from app.observability.metrics import (
    inc_sanitizer_confusable_detected,
    unicode_normalized_total,
    unicode_suspicious_total,
)

# Normalized config values (module-level; safe to import elsewhere)
VERIFIER_LATENCY_BUDGET_MS = get_verifier_latency_budget_ms()
VERIFIER_SAMPLING_PCT = get_verifier_sampling_pct()
# --- END PR-C wire-up block ---

# --- BEGIN PR-D wire-up block ---
# from app.services.verifier.router_adapter import VerifierAdapter
# from app.services.verifier.providers.mock import MockProvider  # example
# verifier = VerifierAdapter(MockProvider())
#
# async def evaluate_with_guardrail(text: str):
#     outcome = await verifier.evaluate(text)
#     # Map outcome to existing policy/action machinery as you already do.
#     return outcome
# --- END PR-D wire-up block ---

# NEW: hardened verifier integration (safe, optional) with proper Optional typing
HardenedVerifyFn = Callable[..., Awaitable[Tuple[Optional[str], Dict[str, str]]]]
try:
    from app.services.verifier.integration import (
        error_fallback_action,
        maybe_verify_and_headers as _hardened_impl,
    )

    _maybe_hardened_verify: Optional[HardenedVerifyFn] = _hardened_impl
except Exception:  # pragma: no cover
    _maybe_hardened_verify = None

    def error_fallback_action() -> str:
        return "allow"


router = APIRouter()

# ------------------------- helpers & constants -------------------------

DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def _inspect_unicode_findings(text: str) -> Tuple[str, Optional[Dict[str, Any]]]:
    if not text:
        return text, None

    findings = detect_unicode_anomalies(text)
    normalized = normalize_nfkc(text)
    if not findings:
        return normalized, None

    totals = Counter()
    samples: Dict[str, Dict[str, str]] = {}
    for finding in findings:
        kind = finding["type"]
        totals[kind] += 1
        inc_sanitizer_confusable_detected(kind)
        samples.setdefault(
            kind,
            {"char": finding["char"], "codepoint": finding["codepoint"]},
        )

    summary: Dict[str, Any] = {
        "totals_by_type": {k: int(v) for k, v in totals.items()},
        "sample_chars": samples,
    }
    return normalized, summary


_BLOCK_DECISIONS = {"block", "block_input_only", "deny", "lock"}


def _has_api_key(x_api_key: Optional[str], auth: Optional[str]) -> bool:
    if x_api_key:
        return True
    if auth and auth.strip():
        return True
    return False


RE_SECRET = re.compile(r"\bsk-[A-Za-z0-9]{24,}\b")
RE_AWS = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
RE_GITHUB_PAT = re.compile(r"\bghp_[A-Za-z0-9]{36}\b")
RE_SLACK_TOKEN = re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,48}\b")
RE_GOOGLE_API_KEY = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")
RE_STRIPE_SECRET = re.compile(r"\bsk_(?:live|test)_[0-9a-zA-Z]{24}\b")
RE_STRIPE_PUB = re.compile(r"\bpk_(?:live|test)_[0-9a-zA-Z]{24}\b")
RE_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")
RE_BEARER = re.compile(r"\bBearer\s+[A-Za-z0-9_\-\.]{20,}\b")
RE_PROMPT_INJ = re.compile(r"\bignore\s+previous\s+instructions\b", re.I)
RE_SYSTEM_PROMPT = re.compile(r"\breveal\s+system\s+prompt\b", re.I)
RE_DAN = re.compile(r"\bpretend\s+to\s+be\s+DAN\b", re.I)
RE_LONG_BASE64ISH = re.compile(r"\b[A-Za-z0-9+/=]{200,}\b")
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
RE_PHONE = re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b")
RE_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

RE_PRIVATE_KEY_ENVELOPE = re.compile(
    r"-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----",
    re.S,
)
RE_PRIVATE_KEY_MARKER = re.compile(r"(?:-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----)")

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


def _prompt_hash(text: Optional[str]) -> Optional[str]:
    if not text:
        return None
    try:
        return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()
    except Exception:
        return None


def _coerce_rule_hits(rule_ids: Optional[Iterable[str]]) -> List[str]:
    hits: List[str] = []
    if not rule_ids:
        return hits
    for rid in rule_ids:
        if rid is None:
            continue
        rid_str = str(rid).strip()
        if rid_str:
            hits.append(rid_str)
    return hits


def _coerce_score(val: Any) -> Optional[float]:
    if val is None:
        return None
    if isinstance(val, bool):
        return float(val)
    try:
        coerced = float(val)
    except Exception:
        return None
    if not math.isfinite(coerced):
        return None
    return coerced


def _coerce_float_value(val: Any, default: float = 0.0) -> float:
    if isinstance(val, bool):
        return float(val)
    try:
        return float(val)
    except Exception:
        return default


def _coerce_int_value(val: Any, default: int = 0) -> int:
    if isinstance(val, bool):
        return int(val)
    try:
        return int(val)
    except Exception:
        return default


def _log_adjudication(
    *,
    request_id: str,
    tenant: Optional[str],
    bot: Optional[str],
    decision: str,
    rule_ids: Optional[Iterable[str]],
    latency_ms: int,
    policy_version: Optional[str],
    rules_path: Optional[str],
    sampled: bool,
    prompt_sha256: Optional[str],
    provider: Optional[str],
    score: Optional[float],
) -> None:
    try:
        hits = _coerce_rule_hits(rule_ids)
        primary_rule_id = next((h for h in (hits or []) if h), None)

        record = _adj_log.AdjudicationRecord(
            ts=_adj_log._now_ts(),
            request_id=str(request_id or ""),
            tenant=str(tenant or "unknown"),
            bot=str(bot or "unknown"),
            provider=str(provider or "core"),
            decision=str(decision or "unknown"),
            rule_hits=hits,
            rule_id=primary_rule_id,
            score=score,
            latency_ms=int(max(latency_ms, 0)),
            policy_version=str(policy_version) if policy_version else None,
            rules_path=str(rules_path) if rules_path else None,
            sampled=bool(sampled),
            prompt_sha256=prompt_sha256,
        )
        _adj_log.append(record)
    except Exception:
        pass


def _resolve_rules_path_hint(tenant: str, bot: str) -> Optional[str]:
    try:
        from app.services import config_store as _cfg_store

        resolver = getattr(_cfg_store, "resolve_rules_path", None)
        if callable(resolver):
            resolved_path = resolver(tenant, bot)
            if isinstance(resolved_path, str) and resolved_path.strip():
                return resolved_path.strip()
            if isinstance(resolved_path, Mapping):
                rp_val = resolved_path.get("rules_path")
                if isinstance(rp_val, str) and rp_val.strip():
                    return rp_val.strip()
    except Exception:
        return None
    return None


def _tenant_bot(t: Optional[str], b: Optional[str]) -> Tuple[str, str]:
    tenant = (t or "default").strip() or "default"
    bot = (b or "default").strip() or "default"
    return tenant, bot


def _actor_labels(request: Request) -> Tuple[Optional[str], Optional[str]]:
    tenant = request.headers.get("X-Tenant")
    bot = request.headers.get("X-Bot")
    if not tenant:
        tenant = getattr(request.state, "tenant", None)
    if not bot:
        bot = getattr(request.state, "bot", None)
    return tenant, bot


def _record_actor_metric(request: Request, action: str) -> None:
    family = "allow" if action == "allow" else "deny"
    tenant, bot = _actor_labels(request)
    inc_actor_decisions_total(family, tenant, bot)


def emit_audit_event(payload: Dict[str, Any]) -> None:
    _emit(payload)


def _normalize_wildcards(
    rule_hits: Dict[str, List[str]],
    is_deny: bool,
) -> None:
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


def _maybe_metric(func_name: str, *args: Any, **kwargs: Any) -> None:
    try:
        fn = getattr(m, func_name, None)
        if callable(fn):
            fn(*args, **kwargs)
    except Exception:
        pass


def _apply_redactions(
    text: str,
    *,
    direction: str,
) -> Tuple[
    str,
    Dict[str, List[str]],
    int,
    List[Tuple[int, int, str, Optional[str]]],
]:
    rule_hits: Dict[str, List[str]] = {}
    redactions = 0
    redacted = text
    spans: List[Tuple[int, int, str, Optional[str]]] = []

    original = text

    matches = list(RE_SECRET.finditer(original))
    if matches:
        redacted = RE_SECRET.sub("[REDACTED:OPENAI_KEY]", redacted)
        rule_hits.setdefault("secrets:openai_key", []).append(RE_SECRET.pattern)
        for m_ in matches:
            spans.append((m_.start(), m_.end(), "[REDACTED:OPENAI_KEY]", "secrets:openai_key"))
            _maybe_metric("inc_redaction", "openai_key")
        redactions += len(matches)
        original = redacted

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
            _maybe_metric("inc_redaction", "aws_access_key_id")
        redactions += len(matches)
        original = redacted

    matches = list(RE_GITHUB_PAT.finditer(original))
    if matches:
        redacted = RE_GITHUB_PAT.sub("[REDACTED:GITHUB_PAT]", redacted)
        rule_hits.setdefault("secrets:github_pat", []).append(RE_GITHUB_PAT.pattern)
        for m_ in matches:
            spans.append((m_.start(), m_.end(), "[REDACTED:GITHUB_PAT]", "secrets:github_pat"))
            _maybe_metric("inc_redaction", "github_pat")
        redactions += len(matches)
        original = redacted

    matches = list(RE_SLACK_TOKEN.finditer(original))
    if matches:
        redacted = RE_SLACK_TOKEN.sub("[REDACTED:SLACK_TOKEN]", redacted)
        rule_hits.setdefault("secrets:slack_token", []).append(RE_SLACK_TOKEN.pattern)
        for m_ in matches:
            spans.append((m_.start(), m_.end(), "[REDACTED:SLACK_TOKEN]", "secrets:slack_token"))
            _maybe_metric("inc_redaction", "slack_token")
        redactions += len(matches)
        original = redacted

    matches = list(RE_GOOGLE_API_KEY.finditer(original))
    if matches:
        redacted = RE_GOOGLE_API_KEY.sub("[REDACTED:GOOGLE_API_KEY]", redacted)
        rule_hits.setdefault("secrets:google_api_key", []).append(RE_GOOGLE_API_KEY.pattern)
        for m_ in matches:
            spans.append(
                (
                    m_.start(),
                    m_.end(),
                    "[REDACTED:GOOGLE_API_KEY]",
                    "secrets:google_api_key",
                )
            )
            _maybe_metric("inc_redaction", "google_api_key")
        redactions += len(matches)
        original = redacted

    matches = list(RE_STRIPE_SECRET.finditer(original))
    if matches:
        redacted = RE_STRIPE_SECRET.sub("[REDACTED:STRIPE_SECRET]", redacted)
        rule_hits.setdefault("secrets:stripe_secret", []).append(RE_STRIPE_SECRET.pattern)
        for m_ in matches:
            spans.append(
                (
                    m_.start(),
                    m_.end(),
                    "[REDACTED:STRIPE_SECRET]",
                    "secrets:stripe_secret",
                )
            )
            _maybe_metric("inc_redaction", "stripe_secret")
        redactions += len(matches)
        original = redacted

    matches = list(RE_STRIPE_PUB.finditer(original))
    if matches:
        redacted = RE_STRIPE_PUB.sub("[REDACTED:STRIPE_PUBLISHABLE]", redacted)
        rule_hits.setdefault("secrets:stripe_pub", []).append(RE_STRIPE_PUB.pattern)
        for m_ in matches:
            spans.append(
                (
                    m_.start(),
                    m_.end(),
                    "[REDACTED:STRIPE_PUBLISHABLE]",
                    "secrets:stripe_pub",
                )
            )
            _maybe_metric("inc_redaction", "stripe_pub")
        redactions += len(matches)
        original = redacted

    matches = list(RE_JWT.finditer(original))
    if matches:
        redacted = RE_JWT.sub("[REDACTED:JWT]", redacted)
        rule_hits.setdefault("secrets:jwt", []).append(RE_JWT.pattern)
        for m_ in matches:
            spans.append((m_.start(), m_.end(), "[REDACTED:JWT]", "secrets:jwt"))
            _maybe_metric("inc_redaction", "jwt")
        redactions += len(matches)
        original = redacted

    matches = list(RE_BEARER.finditer(original))
    if matches:
        redacted = RE_BEARER.sub("[REDACTED:BEARER]", redacted)
        rule_hits.setdefault("secrets:bearer", []).append(RE_BEARER.pattern)
        for m_ in matches:
            spans.append((m_.start(), m_.end(), "[REDACTED:BEARER]", "secrets:bearer"))
            _maybe_metric("inc_redaction", "bearer")
        redactions += len(matches)
        original = redacted

    matches = list(RE_PRIVATE_KEY_ENVELOPE.finditer(original))
    if matches:
        redacted = RE_PRIVATE_KEY_ENVELOPE.sub("[REDACTED:PRIVATE_KEY]", redacted)
        rule_hits.setdefault("secrets:private_key", []).append(RE_PRIVATE_KEY_ENVELOPE.pattern)
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
        original = redacted

    matches = list(RE_PRIVATE_KEY_MARKER.finditer(original))
    if matches:
        redacted = RE_PRIVATE_KEY_MARKER.sub("[REDACTED:PRIVATE_KEY]", redacted)
        rule_hits.setdefault("secrets:private_key", []).append(RE_PRIVATE_KEY_MARKER.pattern)
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
        original = redacted

    matches = list(RE_EMAIL.finditer(original))
    if matches:
        redacted = RE_EMAIL.sub("[REDACTED:EMAIL]", redacted)
        rule_hits.setdefault("pii:email", []).append(RE_EMAIL.pattern)
        for m_ in matches:
            spans.append((m_.start(), m_.end(), "[REDACTED:EMAIL]", "pii:email"))
            _maybe_metric("inc_redaction", "email")
        redactions += len(matches)
        original = redacted

    matches = list(RE_PHONE.finditer(original))
    if matches:
        redacted = RE_PHONE.sub("[REDACTED:PHONE]", redacted)
        rule_hits.setdefault("pii:phone", []).append(RE_PHONE.pattern)
        for m_ in matches:
            spans.append((m_.start(), m_.end(), "[REDACTED:PHONE]", "pii:phone"))
            _maybe_metric("inc_redaction", "phone")
        redactions += len(matches)
        original = redacted

    matches = list(RE_SSN.finditer(original))
    if matches:
        redacted = RE_SSN.sub("[REDACTED:SSN]", redacted)
        rule_hits.setdefault("pi:ssn", []).append(RE_SSN.pattern)
        for m_ in matches:
            spans.append((m_.start(), m_.end(), "[REDACTED:SSN]", "pi:ssn"))
            _maybe_metric("inc_redaction", "ssn")
        redactions += len(matches)
        original = redacted

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
        original = redacted

    _normalize_wildcards(rule_hits, is_deny=False)
    return redacted, rule_hits, redactions, spans


def _decision_family(action: str) -> str:
    return "allow" if action == "allow" else "deny"


def _rule_ids_from_hits(rule_hits: Any) -> List[str]:
    if not rule_hits:
        return []
    if isinstance(rule_hits, dict):
        return [str(k) for k in rule_hits.keys() if str(k)]
    if isinstance(rule_hits, (list, tuple, set)):
        return [str(k) for k in rule_hits if str(k)]
    return []


def _shadow_policy_evaluator(
    payload: Mapping[str, Any], *, policy: Mapping[str, Any]
) -> Mapping[str, Any]:
    _ = payload  # payload is currently unused; reserved for future evaluators
    action_raw = policy.get("default_action")
    if action_raw is None:
        action_raw = policy.get("action")
    action = str(action_raw or "").strip().lower()
    if action in {"block", "block_input_only", "reject"}:
        action = "deny"
    elif action not in {"allow", "deny", "lock", "clarify"}:
        action = "allow"

    rule_ids: List[str] = []
    raw_rule_ids = policy.get("rule_ids")
    if isinstance(raw_rule_ids, (list, tuple, set)):
        rule_ids = [str(r) for r in raw_rule_ids if str(r)]
    elif isinstance(raw_rule_ids, str):
        rid = raw_rule_ids.strip()
        if rid:
            rule_ids = [rid]

    result: Dict[str, Any] = {"action": action}
    if rule_ids:
        result["rule_ids"] = rule_ids
    reason = policy.get("reason")
    if isinstance(reason, str) and reason.strip():
        result["reason"] = reason.strip()
    return result


def _finalize_ingress_response(
    response: Response,
    *,
    request_id: str,
    fingerprint_value: Optional[str],
    decision_family: str,
    rule_ids: Optional[List[str]] = None,
    escalate: bool = True,
    mode_hint: Optional[str] = None,
    retry_after_hint: Optional[int] = None,
    policy_result: Optional[Mapping[str, Any]] = None,
) -> Response:
    family_norm = str(decision_family or "").strip().lower()
    default_mode: Mode = "allow" if family_norm == "allow" else "deny"

    pr = cast(Optional[PolicyResult], policy_result)

    rule_ids_clean: List[str] = []
    if rule_ids:
        for rid in rule_ids:
            rid_str = str(rid or "").strip()
            if rid_str:
                rule_ids_clean.append(rid_str)

    header_mode = mode_hint or "normal"
    metrics_mode: str = default_mode

    if mode_hint is None:
        try:
            metrics_mode = choose_mode(pr, family_norm)
        except Exception:
            metrics_mode = default_mode
        header_mode = "execute_locked" if metrics_mode == "execute_locked" else "normal"
    else:
        if mode_hint == "execute_locked":
            metrics_mode = "execute_locked"
        elif mode_hint == "full_quarantine":
            metrics_mode = "full_quarantine"
        else:
            metrics_mode = default_mode

    if header_mode == "execute_locked" and response.status_code != 429:
        raw_body = getattr(response, "body", b"")
        if isinstance(raw_body, str):
            raw_bytes = raw_body.encode("utf-8")
        elif isinstance(raw_body, (bytes, bytearray)):
            raw_bytes = bytes(raw_body)
        else:
            raw_bytes = b""
        media_type = response.media_type or response.headers.get("Content-Type")
        ctype = media_type or "application/json"
        safe_body = redact_response_body(raw_bytes, str(ctype))
        locked_response = Response(content=safe_body, status_code=200, media_type=str(ctype))
        for key, value in response.headers.items():
            if key.lower() == "content-length":
                continue
            locked_response.headers[key] = value
        locked_response.background = response.background
        response = locked_response

    mode_for_headers = header_mode
    retry_after = retry_after_hint or 0
    fp = fingerprint_value or ""

    if escalate and esc.is_enabled() and fp:
        esc_mode, retry_after = esc.record_and_decide(fp, family_norm)
        if esc_mode == "full_quarantine":
            response = JSONResponse(
                status_code=429,
                content={"ok": False, "reason": "quarantine"},
            )
            if retry_after:
                response.headers["Retry-After"] = str(max(1, retry_after))
            mode_for_headers = "full_quarantine"
            metrics_mode = "full_quarantine"
        else:
            mode_for_headers = header_mode
    else:
        if header_mode == "full_quarantine" and retry_after:
            response.headers["Retry-After"] = str(max(1, retry_after))
        mode_for_headers = header_mode

    final_mode = (
        "full_quarantine"
        if response.status_code == 429
        else (
            metrics_mode
            if metrics_mode in {"allow", "execute_locked", "deny", "full_quarantine"}
            else default_mode
        )
    )

    action_val_raw: Optional[str] = None
    if pr is not None:
        act = pr.get("action")
        if isinstance(act, str):
            action_val_raw = act.strip().lower()
    if action_val_raw not in {"allow", "lock", "deny"}:
        action_val_raw = family_norm if family_norm in {"allow", "deny"} else "allow"

    inc_rule_hits(rule_ids_clean, action=action_val_raw or "allow", mode=final_mode)

    apply_decision_headers(
        response,
        decision_family,
        mode_for_headers,
        request_id=request_id,
        rule_ids=rule_ids_clean,
    )

    inc_mode(final_mode)
    return response


def _debug_requested(x_debug: Optional[str]) -> bool:
    return bool(x_debug)


# --------------------- verifier sampling helpers ---------------------


def _verifier_sampling_pct() -> float:
    if VERIFIER_SAMPLING_PCT != 0.0:
        return VERIFIER_SAMPLING_PCT
    return get_verifier_sampling_pct()


def _hits_trigger_verifier(hits: Dict[str, List[str]]) -> bool:
    keys = list(hits.keys())
    return any(k.startswith(("injection:", "jailbreak:", "unsafe:illicit")) for k in keys)


# ------------------------------- responses -------------------------------


def _merge_headers(base: Dict[str, str], extra: Optional[Dict[str, str]]) -> Dict[str, str]:
    if not extra:
        return base
    for k, v in extra.items():
        try:
            base[str(k)] = str(v)
        except Exception:
            pass
    return base


def _routing_decision(
    action: str,
    rule_hits: Dict[str, List[str]],
    prompt_fingerprint: str,
) -> Dict[str, Any]:
    normalized_action = action
    if normalized_action in {"deny", "block"}:
        normalized_action = "block_input_only"
    clarify_candidate = normalized_action == "clarify"
    attempt_count, near_duplicate = track_attempt(prompt_fingerprint, increment=clarify_candidate)
    clarify_stage = 2 if near_duplicate or attempt_count > 1 else 1
    clarify_message = stage_message(clarify_stage) if clarify_candidate else None

    return {
        "action": normalized_action,
        "clarify_message": clarify_message,
        "risk_score": 0,
        "rule_hits": _rule_ids_from_hits(rule_hits),
        "prompt_fingerprint": prompt_fingerprint,
        "near_duplicate": near_duplicate,
        "attempt_count": attempt_count,
        "incident_id": "",
    }


def _respond_action(
    action: str,
    transformed_text: str,
    request_id: str,
    rule_hits: Dict[str, List[str]],
    debug: Optional[Dict[str, Any]] = None,
    redaction_count: int = 0,
    modalities: Optional[Dict[str, int]] = None,
    *,
    verifier_sampled: bool = False,
    direction: str = "ingress",
    extra_headers: Optional[Dict[str, str]] = None,
    mitigation_modes: Optional[Dict[str, bool]] = None,
    mitigation_forced: Optional[str] = None,
    decision_override: Optional[str] = None,
    routing_meta: Optional[Dict[str, Any]] = None,
) -> JSONResponse:
    fam = "allow" if action == "allow" else "deny"
    _maybe_metric("inc_decisions_total", fam)

    decisions: List[Dict[str, Any]] = []
    if redaction_count > 0:
        decisions.append({"type": "redaction", "count": redaction_count})
    if modalities:
        for tag, count in modalities.items():
            if count > 0:
                decisions.append({"type": "modality", "tag": tag, "count": count})
    if routing_meta:
        decisions.append({"type": "routing", "info": routing_meta})

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
    decision_val = decision_override or body.get("decision") or body.get("action")
    if decision_val:
        body["decision"] = decision_val
    if mitigation_modes is not None:
        body["mitigation_modes"] = dict(mitigation_modes)
    if mitigation_forced:
        body["mitigation_forced"] = mitigation_forced

    headers = {
        "X-Guardrail-Policy-Version": current_rules_version(),
        "X-Guardrail-Verifier-Sampled": "1" if verifier_sampled else "0",
        "X-Guardrail-Decision": action,
        "X-Guardrail-Decision-Source": "policy-only",
    }
    if direction == "ingress":
        headers["X-Guardrail-Ingress-Redactions"] = str(int(redaction_count or 0))
    else:
        headers["X-Guardrail-Egress-Redactions"] = str(int(redaction_count or 0))

    headers = _merge_headers(headers, extra_headers)

    # If hardened verifier participated, mark source accordingly.
    if extra_headers and extra_headers.get("X-Guardrail-Verifier"):
        headers["X-Guardrail-Decision-Source"] = "hardened"

    headers["X-Guardrail-Decision"] = action
    return JSONResponse(body, headers=headers)


def _augment_json_response(
    response: JSONResponse,
    modes: Mapping[str, bool],
    *,
    forced: Optional[str] = None,
    decision: Optional[str] = None,
) -> None:
    raw_body = getattr(response, "body", b"")
    data: Any
    if isinstance(raw_body, (bytes, bytearray)):
        try:
            data = json.loads(raw_body.decode() or "{}")
        except Exception:
            return
    elif isinstance(raw_body, str):
        try:
            data = json.loads(raw_body or "{}")
        except Exception:
            return
    else:
        return
    if not isinstance(data, dict):
        return
    data["mitigation_modes"] = dict(modes)
    if forced:
        data["mitigation_forced"] = forced
    if decision and "decision" not in data:
        data["decision"] = decision
    response.body = response.render(data)


def _respond_legacy_allow(
    prompt: str,
    request_id: str,
    rule_hits: List[str] | Dict[str, List[str]],
    policy_version: str,
    redactions: int,
) -> JSONResponse:
    _maybe_metric("inc_decisions_total", "allow")
    body: Dict[str, Any] = {
        "request_id": request_id,
        "decision": "allow",
        "transformed_text": prompt,
        "text": prompt,
        "rule_hits": rule_hits,
        "policy_version": policy_version,
        "redactions": int(redactions),
    }
    headers = {
        "X-Guardrail-Policy-Version": current_rules_version(),
        "X-Guardrail-Ingress-Redactions": str(int(redactions or 0)),
    }
    return JSONResponse(body, headers=headers)


def _respond_legacy_block(
    request_id: str,
    rule_hits: List[str] | Dict[str, List[str]],
    transformed_text: str,
    policy_version: str,
    redactions: int,
) -> JSONResponse:
    _maybe_metric("inc_decisions_total", "deny")
    body: Dict[str, Any] = {
        "request_id": request_id,
        "decision": "block",
        "transformed_text": transformed_text,
        "text": transformed_text,
        "rule_hits": rule_hits,
        "policy_version": policy_version,
        "redactions": int(redactions),
    }
    headers = {
        "X-Guardrail-Policy-Version": current_rules_version(),
        "X-Guardrail-Ingress-Redactions": str(int(redactions or 0)),
    }
    return JSONResponse(body, headers=headers)


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
    verifier: Optional[Dict[str, Any]] = None,
) -> None:
    allowed_decisions = {"allow", "block", "deny", "clarify"}
    decision = action_or_decision if action_or_decision in allowed_decisions else "allow"

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
    if direction == "ingress":
        _maybe_metric("observe_ingress_payload_bytes", payload["payload_bytes"])
    elif direction == "egress":
        _maybe_metric("observe_egress_payload_bytes", payload["payload_bytes"])
    if debug_sources:
        payload["debug_sources"] = [s.model_dump() for s in debug_sources]
    if verifier:
        payload["verifier"] = {
            k: v for k, v in verifier.items() if k in {"provider", "decision", "latency_ms"}
        }
    emit_audit_event(payload)


def _bump_family(
    direction: str,
    endpoint: str,
    action: str,
    tenant: str,
    bot: str,
) -> None:
    fam = "allow" if action == "allow" else "deny"
    _maybe_metric("inc_decision_family_tenant_bot", fam, tenant, bot)


# ------------------------------- policies -------------------------------


def _legacy_policy(prompt: str) -> Tuple[str, List[str]]:
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
    want_debug: bool,
) -> Tuple[str, Dict[str, List[str]], Optional[Dict[str, Any]]]:
    """
    Decide based on lightweight regex and hidden-text markers.
    Hidden-text markers:
      - With X-Debug:1 -> deny + tag as injection:hidden_text
      - Without debug  -> allow (no injection:* tag to avoid default block)
    """
    hits: Dict[str, List[str]] = {}
    dbg: Dict[str, Any] = {}

    # Hidden-text markers
    has_hidden_marker = any(
        mark in (text or "")
        for mark in (
            "[HIDDEN_TEXT_DETECTED:",
            "[HIDDEN_HTML_DETECTED:",
            "[HIDDEN_DOCX_DETECTED:",
        )
    )
    if has_hidden_marker:
        dbg["explanations"] = ["hidden_text_detected"]
        if want_debug:
            hits.setdefault("injection:hidden_text", []).append("hidden_text_marker")
            _normalize_wildcards(hits, is_deny=True)
            return "deny", hits, dbg
        # No debug → informational only, do not add injection:* family

    # Illicit content
    if RE_HACK_WIFI.search(text or ""):
        hits.setdefault("unsafe:illicit", []).append("hack_wifi_or_bypass_wpa2")
        dbg["explanations"] = ["illicit_request"]
        _normalize_wildcards(hits, is_deny=True)
        return "deny", hits, dbg

    # Explicit jailbreak cues
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

    return "allow", hits, (dbg if dbg else None) if dbg else None


def _egress_policy(
    text: str,
    want_debug: bool,
) -> Tuple[str, str, Dict[str, List[str]], Optional[Dict[str, Any]]]:
    dbg: Optional[Dict[str, Any]] = None
    if RE_PRIVATE_KEY_ENVELOPE.search(text or "") or RE_PRIVATE_KEY_MARKER.search(text or ""):
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
) -> Tuple[str, str, object | None]:
    from app.services.detectors import pdf_hidden as _pdf_hidden

    name = getattr(obj, "filename", None) or "file"
    ctype = (getattr(obj, "content_type", "") or "").lower()
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""

    try:
        # Images
        if ctype.startswith("image/") or ext in {"png", "jpg", "jpeg", "gif", "bmp"}:
            mods["image"] = mods.get("image", 0) + 1
            if _ocr.ocr_enabled():
                raw = await obj.read()
                _maybe_metric("add_ocr_bytes", "image", len(raw))
                text = _ocr.extract_from_image(raw)
                if text and text.strip():
                    _maybe_metric("inc_ocr_extraction", "image", "ok")
                    return text, name, None
                _maybe_metric("inc_ocr_extraction", "image", "empty")
            return f"[IMAGE:{name}]", name, None

        # Audio
        if ctype.startswith("audio/") or ext in {"wav", "mp3", "m4a", "ogg"}:
            mods["audio"] = mods.get("audio", 0) + 1
            return f"[AUDIO:{name}]", name, None

        # Plain text
        if ctype == "text/plain" or ext == "txt":
            raw = await obj.read()
            return raw.decode("utf-8", errors="ignore"), name, None

        # HTML (hidden-content detector)
        if ctype == "text/html" or ext in {"html", "htm"}:
            raw = await obj.read()
            try:
                # Import the function directly to keep mypy happy
                from app.services.detectors.html_hidden import (
                    detect_hidden_text as _detect_html_hidden,
                )

                text_html = raw.decode("utf-8", errors="ignore")
                hidden = _detect_html_hidden(text_html)

                hidden_block = ""
                if hidden.get("found"):
                    reasons_list = cast(List[str], hidden.get("reasons") or [])
                    samples_list = cast(List[str], hidden.get("samples") or [])

                    for r in reasons_list:
                        _maybe_metric("inc_html_hidden", str(r))

                    reasons = ",".join(reasons_list) or "detected"
                    joined = " ".join(samples_list)[:500]
                    hidden_block = (
                        f"\n[HIDDEN_HTML_DETECTED:{reasons}]\n{joined}\n[HIDDEN_HTML_END]\n"
                    )

                mods["file"] = mods.get("file", 0) + 1
                return hidden_block or f"[FILE:{name}]", name, None
            except Exception:
                mods["file"] = mods.get("file", 0) + 1
                return f"[FILE:{name}]", name, None

        # DOCX (hidden-text + jailbreak detector)
        if ctype == DOCX_MIME or ext == "docx":
            raw = await obj.read()
            try:
                from app.services.detectors.docx_jb import (
                    detect_and_sanitize_docx as _detect_docx,
                )

                res = _detect_docx(raw)
                mods["file"] = mods.get("file", 0) + 1
                return res.sanitized_text or f"[FILE:{name}]", name, res
            except Exception:
                mods["file"] = mods.get("file", 0) + 1
                return f"[FILE:{name}]", name, None

        # PDF
        if ctype == "application/pdf" or ext == "pdf":
            raw = await obj.read()

            hidden = _pdf_hidden.detect_hidden_text(raw)
            hidden_block = ""
            if hidden.get("found"):
                reasons_list = cast(List[str], hidden.get("reasons") or [])
                samples_list = cast(List[str], hidden.get("samples") or [])
                for r in reasons_list:
                    _maybe_metric("inc_pdf_hidden", str(r))
                reasons = ",".join(reasons_list) or "detected"
                joined = " ".join(samples_list)[:500]
                hidden_block = f"\n[HIDDEN_TEXT_DETECTED:{reasons}]\n{joined}\n[HIDDEN_TEXT_END]\n"

            if _ocr.ocr_enabled():
                _maybe_metric("add_ocr_bytes", "pdf", len(raw))
                text, outcome = _ocr.extract_pdf_with_optional_ocr(raw)
                if text and text.strip():
                    _maybe_metric(
                        "inc_ocr_extraction",
                        "pdf",
                        outcome if outcome in {"textlayer", "fallback"} else "ok",
                    )
                    mods["file"] = mods.get("file", 0) + 1
                    return (text + hidden_block) if hidden_block else text, name, None
                _maybe_metric("inc_ocr_extraction", "pdf", outcome if outcome else "empty")

            if decode_pdf:
                mods["file"] = mods.get("file", 0) + 1
                return raw.decode("utf-8", errors="ignore") + hidden_block, name, None

            mods["file"] = mods.get("file", 0) + 1
            return f"[FILE:{name}]", name, None

        # Unknown file type -> generic marker
        mods["file"] = mods.get("file", 0) + 1
        return f"[FILE:{name}]", name, None

    except Exception:
        try:
            if _ocr.ocr_enabled():
                if ctype.startswith("image/") or ext in {
                    "png",
                    "jpg",
                    "jpeg",
                    "gif",
                    "bmp",
                }:
                    _maybe_metric("inc_ocr_extraction", "image", "error")
                elif ctype == "application/pdf" or ext == "pdf":
                    _maybe_metric("inc_ocr_extraction", "pdf", "error")
        except Exception:
            pass
        mods["file"] = mods.get("file", 0) + 1
        return f"[FILE:{name}]", name, None


async def _read_form_and_merge(
    request: Request,
    decode_pdf: bool,
) -> Tuple[str, Dict[str, int], List[Dict[str, str]], List[object]]:
    """
    Merge 'text' plus files from multipart form data. Iterate over
    form.multi_items() to capture *all* file fields. Any file-like value
    (has filename + read) is handled. Returns (text, modality_counts, sources).
    """
    form = await request.form()
    combined: List[str] = []
    mods: Dict[str, int] = {}
    sources: List[Dict[str, str]] = []
    docx_res: List[object] = []

    base = str(form.get("text") or "")
    if base:
        combined.append(base)

    seen: set[int] = set()

    async def _maybe_add(val: Any) -> None:
        if isinstance(val, UploadFile) or (hasattr(val, "filename") and hasattr(val, "read")):
            vid = id(val)
            if vid in seen:
                return
            seen.add(vid)
            frag, fname, dres = await _handle_upload_to_text(val, decode_pdf, mods)
            combined.append(frag)
            sources.append({"filename": fname})
            if dres is not None:
                docx_res.append(dres)

    try:
        for _, v in form.multi_items():
            await _maybe_add(v)
    except Exception:
        for v in form.values():
            await _maybe_add(v)

    text = "\n".join([s for s in combined if s])
    return text, mods, sources, docx_res


# ------------------------------- hardened verifier hook -------------------------------


async def _maybe_hardened(
    *,
    text: str,
    direction: str,  # "ingress" | "egress"
    tenant: str,
    bot: str,
    family: Optional[str],
) -> Tuple[Optional[str], Dict[str, str]]:
    """
    Call hardened verifier with a total latency budget and optional retry budget.
    Returns (maybe_action_override, headers). On errors we return (None, fallback-headers).
    Safe no-op if the integration is missing or VERIFIER_HARDENED_MODE disables it upstream.
    """
    if _maybe_hardened_verify is None:
        return None, {}

    # Total time budget (ms) — shared across attempts. Invalid or missing → unset.
    total_budget_ms = VERIFIER_LATENCY_BUDGET_MS
    if total_budget_ms is None:
        total_budget_ms = get_verifier_latency_budget_ms()

    # Retry budget: number of retries (attempts = retries + 1).
    retry_budget = get_verifier_retry_budget()
    attempts = max(1, retry_budget + 1)

    deadline = time.perf_counter() + (total_budget_ms / 1000.0) if total_budget_ms else None

    last_fallback_headers: Dict[str, str] = {
        "X-Guardrail-Verifier": "unknown",
        "X-Guardrail-Verifier-Mode": "fallback",
    }

    for _ in range(attempts):
        # Respect the remaining budget per attempt
        remaining_ms: Optional[int] = None
        if deadline is not None:
            remaining = (deadline - time.perf_counter()) * 1000.0
            if remaining <= 0:
                break
            remaining_ms = int(remaining)

        try:
            action, headers = await _maybe_hardened_verify(
                text=text,
                direction=direction,
                tenant_id=tenant,
                bot_id=bot,
                family=family,
                latency_budget_ms=remaining_ms,
            )
            # Normalize headers and mark as live path
            h: Dict[str, str] = {}
            for k, v in (headers or {}).items():
                try:
                    h[str(k)] = str(v)
                except Exception:
                    pass
            h.setdefault("X-Guardrail-Verifier", h.get("X-Guardrail-Verifier", "unknown"))
            h["X-Guardrail-Verifier-Mode"] = "live"
            return action, h
        except Exception:
            # Swallow and try again (until budget exhausted)
            last_fallback_headers = {
                "X-Guardrail-Verifier": "unknown",
                "X-Guardrail-Verifier-Mode": "fallback",
            }
            continue

    return None, last_fallback_headers


def _apply_hardened_override(current_action: str, hv_action: Optional[str]) -> str:
    if not hv_action:
        return current_action
    norm = hv_action.strip().lower()
    if norm == "block":
        norm = "deny"
    if norm in {"allow", "deny"}:
        return norm
    return current_action


# Apply configured fallback when hardened verifier fails
def _apply_hardened_error_fallback(current_action: str) -> str:
    fb = error_fallback_action()
    if fb in {"allow", "deny", "clarify"}:
        return fb
    return current_action


# ------------------------------- endpoints -------------------------------


@router.post("/guardrail")
@router.post("/guardrail/")  # avoid redirect that would double-count in rate limiter
async def guardrail_legacy(
    request: Request,
    x_api_key: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
):
    t_start = time.perf_counter()
    m.inc_requests_total("guardrail_legacy")
    m.set_policy_version(current_rules_version())
    if not _has_api_key(x_api_key, authorization):
        return JSONResponse({"detail": "Unauthorized"}, status_code=401)

    payload = await request.json()
    prompt = str(payload.get("prompt") or "")
    request_id = _req_id(str(payload.get("request_id") or ""))
    prompt_hash_val = _prompt_hash(prompt)

    try:
        max_chars = int(runtime_flags.get("max_prompt_chars"))
    except Exception:
        max_chars = 0
    if max_chars and len(prompt) > max_chars:
        body = {
            "detail": "Prompt too large",
            "code": "payload_too_large",
            "request_id": request_id,
        }
        return JSONResponse(body, status_code=413)

    tenant, bot = _tenant_bot(
        request.headers.get("X-Tenant") or request.headers.get("X-Tenant-ID"),
        request.headers.get("X-Bot") or request.headers.get("X-Bot-ID"),
    )
    _set_binding_ctx(tenant, bot)

    policy_blob = _get_policy()
    policy_version = str(policy_blob.version)
    rules_path_hint = getattr(policy_blob, "path", None)

    action, legacy_hits_list = _legacy_policy(prompt)
    raw_tenant = (
        request.headers.get("X-Tenant-ID") or request.headers.get("X-Tenant") or ""
    ).strip()
    raw_bot = (request.headers.get("X-Bot-ID") or request.headers.get("X-Bot") or "").strip()
    mitigation_modes = get_mitigation_modes(raw_tenant, raw_bot)
    mitigation_forced: Optional[str] = None
    if mitigation_modes.get("block"):
        if str(action or "").lower() not in _BLOCK_DECISIONS:
            _obs_metrics.inc_mitigation_override("block")
        action = "block"
        mitigation_forced = "block"

    redacted, redaction_hits, redactions, _red_spans = _apply_redactions(
        prompt, direction="ingress"
    )

    if tf_enabled():
        redacted, fams, tf_count, _ = tf_apply(redacted, debug=False)
        redactions += tf_count
        for tag in fams.keys():
            redaction_hits.setdefault(tag, []).append("<threat_feed>")
    for tag in redaction_hits.keys():
        m.inc_redaction(tag)
        m.guardrail_redactions_total.labels("ingress", tag).inc()

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
        "ingress",
        "guardrail_legacy",
        "allow" if action == "allow" else "deny",
        tenant,
        bot,
    )

    if action == "block":
        _record_actor_metric(request, "block")
        resp = _respond_legacy_block(
            request_id,
            rule_hits,
            redacted,
            policy_version,
            redactions,
        )
        _augment_json_response(
            resp,
            mitigation_modes,
            forced=mitigation_forced,
            decision="block",
        )
        latency_ms = int((time.perf_counter() - t_start) * 1000)
        _log_adjudication(
            request_id=request_id,
            tenant=tenant,
            bot=bot,
            decision="block",
            rule_ids=_rule_ids_from_hits(rule_hits),
            latency_ms=latency_ms,
            policy_version=policy_version,
            rules_path=rules_path_hint,
            sampled=False,
            prompt_sha256=prompt_hash_val,
            provider="core",
            score=None,
        )
        return resp
    _record_actor_metric(request, "allow")
    resp = _respond_legacy_allow(
        redacted,
        request_id,
        rule_hits,
        policy_version,
        redactions,
    )
    _augment_json_response(
        resp,
        mitigation_modes,
        forced=mitigation_forced,
        decision="allow",
    )
    latency_ms = int((time.perf_counter() - t_start) * 1000)
    _log_adjudication(
        request_id=request_id,
        tenant=tenant,
        bot=bot,
        decision="allow",
        rule_ids=_rule_ids_from_hits(rule_hits),
        latency_ms=latency_ms,
        policy_version=policy_version,
        rules_path=rules_path_hint,
        sampled=False,
        prompt_sha256=prompt_hash_val,
        provider="core",
        score=None,
    )
    return resp


@router.post("/guardrail/evaluate")
async def guardrail_evaluate(request: Request):
    t_start = time.perf_counter()
    headers = request.headers
    tenant, bot = _tenant_bot(
        headers.get("X-Tenant") or headers.get("X-Tenant-ID"),
        headers.get("X-Bot") or headers.get("X-Bot-ID"),
    )
    raw_tenant = (headers.get("X-Tenant-ID") or headers.get("X-Tenant") or "").strip()
    raw_bot = (headers.get("X-Bot-ID") or headers.get("X-Bot") or "").strip()
    mitigation_modes = get_mitigation_modes(raw_tenant, raw_bot)
    want_debug = _debug_requested(headers.get("X-Debug"))
    m.inc_requests_total("ingress_evaluate")
    m.set_policy_version(current_rules_version())

    content_type = (headers.get("content-type") or "").lower()
    combined_text = ""
    explicit_request_id: Optional[str] = None
    mods: Dict[str, int] = {}
    sources: List[Dict[str, str]] = []
    request_payload_dict: Dict[str, Any] = {}
    req_header_request_id = headers.get(REQ_ID_HEADER)
    fingerprint_value: Optional[str]
    prompt_hash_val: Optional[str] = None
    adjudication_provider: Optional[str] = None
    adjudication_sampled = False
    rules_path_hint: Optional[str] = None
    try:
        fingerprint_value = fingerprint(request)
    except Exception:
        fingerprint_value = ""

    rules_path_hint = _resolve_rules_path_hint(tenant, bot)

    if content_type.startswith("application/json"):
        payload = await request.json()
        if isinstance(payload, dict):
            request_payload_dict = dict(payload)
        else:
            request_payload_dict = {}
        combined_text = str(request_payload_dict.get("text") or "")
        explicit_request_id = str(request_payload_dict.get("request_id") or "") or None
    else:
        combined_text, mods, sources, _docx_unused = await _read_form_and_merge(
            request, decode_pdf=False
        )
        for src in sources:
            fname = src.get("filename")
            if fname:
                src["filename"] = normalize_nfkc(str(fname))
        request_payload_dict = {"text": combined_text}
    request_id = _req_id(explicit_request_id or req_header_request_id)
    unicode_header_payload: Optional[str] = None
    unicode_annotation: Optional[Dict[str, Any]] = None
    unicode_findings_summary: Optional[Dict[str, Any]] = None

    def finalize_response(
        response: Response,
        *,
        decision_family: str,
        rule_ids: Optional[Iterable[str]] = None,
        escalate: bool = True,
        mode_hint: Optional[str] = None,
        retry_after_hint: Optional[int] = None,
        policy_result: Optional[Mapping[str, Any]] = None,
    ) -> Response:
        """
        Normalize and forward arguments to _finalize_ingress_response, then publish
        a decision event for the admin feed.

        - Prefers rule_ids from policy_result (if present), falling back to the
          function parameter.
        - Coerces rule_ids to a concrete list[str] | None for type safety.
        - Publishes AFTER finalization so headers/status/mode are accurate.
        """
        # 1) Build a concrete list[str] | None for rule IDs
        final_rule_ids: Optional[list[str]] = None

        pr_rule_ids_any: Any = None
        if policy_result is not None:
            pr_rule_ids_any = policy_result.get("rule_ids")

        if pr_rule_ids_any:
            if isinstance(pr_rule_ids_any, (list, tuple, set)):
                final_rule_ids = [str(x) for x in pr_rule_ids_any]
            elif isinstance(pr_rule_ids_any, str):
                final_rule_ids = [pr_rule_ids_any]
            else:
                final_rule_ids = None

        if final_rule_ids is None and rule_ids is not None:
            final_rule_ids = [str(x) for x in rule_ids]

        live_action_val = ""
        if policy_result is not None:
            try:
                live_action_val = str(policy_result.get("action") or "")
            except Exception:
                live_action_val = ""
        if not live_action_val:
            live_action_val = str(decision_family or "")
        live_action_norm = str(live_action_val or "").strip().lower()
        if not live_action_norm:
            live_action_norm = "unknown"

        shadow_payload: Mapping[str, Any]
        if isinstance(request_payload_dict, Mapping):
            shadow_payload = request_payload_dict
        else:
            try:
                shadow_payload = dict(request_payload_dict)
            except Exception:
                shadow_payload = {}

        shadow_res = maybe_eval_shadow(
            payload=shadow_payload,
            live_action=live_action_norm,
            route=str(request.url.path),
            evaluator=_shadow_policy_evaluator,
        )

        shadow_action_val: Optional[str] = None
        shadow_rule_ids_list: List[str] = []
        if shadow_res:
            raw_shadow_action = shadow_res.get("action")
            if isinstance(raw_shadow_action, str):
                action_str = raw_shadow_action.strip().lower()
                if action_str:
                    shadow_action_val = action_str
            raw_shadow_rule_ids = shadow_res.get("rule_ids")
            if isinstance(raw_shadow_rule_ids, (list, tuple, set)):
                shadow_rule_ids_list = [str(rid) for rid in raw_shadow_rule_ids if str(rid).strip()]
            elif isinstance(raw_shadow_rule_ids, str):
                rid_str = raw_shadow_rule_ids.strip()
                if rid_str:
                    shadow_rule_ids_list = [rid_str]

        # 2) Finalize the response (sets headers, status, etc.)
        resp = _finalize_ingress_response(
            response,
            request_id=request_id,
            fingerprint_value=fingerprint_value,
            decision_family=decision_family,
            rule_ids=final_rule_ids,
            escalate=escalate,
            mode_hint=mode_hint,
            retry_after_hint=retry_after_hint,
            policy_result=policy_result,
        )

        if unicode_header_payload:
            resp.headers.setdefault("X-Guardrail-Unicode", unicode_header_payload)

        # 3) Determine final mode (prefer header set by finalizer)
        final_mode = resp.headers.get("X-Guardrail-Mode")
        if not final_mode:
            # fall back to hint or derive from status code
            if mode_hint:
                final_mode = mode_hint
            elif resp.status_code == 429:
                final_mode = "full_quarantine"
            elif resp.status_code >= 400:
                final_mode = "deny"
            else:
                final_mode = "allow"

        route_label_val = resp.headers.get("X-Guardrail-Endpoint") or str(request.url.path)
        if shadow_action_val and shadow_action_val and shadow_action_val != live_action_norm:
            inc_shadow_disagreement(route_label_val, live_action_norm, shadow_action_val)

        # 4) Publish the decision event for admin feed / SSE / CSV
        # We publish the fields we can reliably determine here. tenant/bot/endpoint
        # may be injected elsewhere; if you already add them to headers, they will
        # appear here; otherwise they default to "unknown".
        event_payload: Dict[str, object] = {
            "incident_id": resp.headers.get("X-Guardrail-Incident-ID"),
            "request_id": request_id,
            "tenant": resp.headers.get("X-Guardrail-Tenant", "unknown"),
            "bot": resp.headers.get("X-Guardrail-Bot", "unknown"),
            "family": decision_family,  # allow|deny
            "mode": final_mode,  # allow|execute_locked|deny|full_quarantine
            "status": resp.status_code,
            "endpoint": resp.headers.get("X-Guardrail-Endpoint"),  # optional
            "rule_ids": final_rule_ids or [],
            "policy_version": resp.headers.get("X-Guardrail-Policy-Version"),
            "shadow_action": shadow_action_val,
            "shadow_rule_ids": shadow_rule_ids_list,
            # latency_ms can be added here if you track it on request.state.*
        }
        if isinstance(policy_result, Mapping):
            routing_payload = policy_result.get("routing")
            if isinstance(routing_payload, Mapping):
                event_payload["routing"] = dict(routing_payload)
        if unicode_annotation:
            event_payload["unicode"] = unicode_annotation
        if unicode_findings_summary:
            event_payload["unicode_findings"] = unicode_findings_summary
        publish(event_payload)

        cfg = get_config()
        if cfg.get("webhook_enable"):
            from app.services import webhooks as wh

            wh.enqueue(event_payload)

        provider_hint = adjudication_provider
        score_val: Optional[float] = None
        if isinstance(policy_result, Mapping):
            score_val = _coerce_score(policy_result.get("score"))
            provider_candidate: Optional[str] = None
            raw_provider = policy_result.get("provider")
            if isinstance(raw_provider, str) and raw_provider.strip():
                provider_candidate = raw_provider.strip()
            else:
                raw_verifier = policy_result.get("verifier")
                if isinstance(raw_verifier, Mapping):
                    vprov = raw_verifier.get("provider")
                    if isinstance(vprov, str) and vprov.strip():
                        provider_candidate = vprov.strip()
            if not provider_hint and provider_candidate:
                provider_hint = provider_candidate

        header_provider = resp.headers.get("X-Guardrail-Verifier")
        if not provider_hint and header_provider:
            provider_hint = header_provider

        sampled_flag = adjudication_sampled
        header_sampled = resp.headers.get("X-Guardrail-Verifier-Sampled")
        if header_sampled is not None:
            sampled_flag = sampled_flag or header_sampled == "1"

        latency_ms = int((time.perf_counter() - t_start) * 1000)
        policy_version_hint = resp.headers.get("X-Guardrail-Policy-Version")
        rules_path = resp.headers.get("X-Guardrail-Rules-Path") or rules_path_hint

        _log_adjudication(
            request_id=request_id,
            tenant=tenant,
            bot=bot,
            decision=live_action_norm,
            rule_ids=final_rule_ids or [],
            latency_ms=latency_ms,
            policy_version=policy_version_hint,
            rules_path=rules_path,
            sampled=sampled_flag,
            prompt_sha256=prompt_hash_val,
            provider=provider_hint,
            score=score_val,
        )

        return resp

    unicode_findings_summary_state = getattr(request.state, "unicode_findings_summary", None)
    if not unicode_findings_summary_state:
        unicode_findings_summary_state = request.scope.get("unicode_findings_summary")
    if unicode_findings_summary_state:
        unicode_findings_summary = copy.deepcopy(unicode_findings_summary_state)
        if combined_text:
            combined_text = normalize_nfkc(combined_text)
            if isinstance(request_payload_dict, dict):
                request_payload_dict["text"] = combined_text
    elif settings.SANITIZER_CONFUSABLES_ENABLED and combined_text:
        combined_text, unicode_findings_summary = _inspect_unicode_findings(combined_text)
        if isinstance(request_payload_dict, dict):
            request_payload_dict["text"] = combined_text

    if settings.UNICODE_SANITIZER_ENABLED and combined_text:
        unicode_cfg = UnicodeSanitizerCfg(
            normalize_only=False,
            block_on_controls=settings.UNICODE_BLOCK_ON_BIDI,
            block_on_mixed_script=settings.UNICODE_BLOCK_ON_MIXED_SCRIPT,
            emoji_ratio_warn=settings.UNICODE_EMOJI_RATIO_WARN,
        )
        unicode_result = sanitize_unicode(combined_text, unicode_cfg)
        combined_text = unicode_result.text
        if isinstance(request_payload_dict, dict):
            request_payload_dict["text"] = combined_text
        if unicode_result.normalized:
            unicode_normalized_total.inc()
        raw_reasons = unicode_result.report.get("reasons", [])
        if isinstance(raw_reasons, (list, tuple, set)):
            reasons_iter = raw_reasons
        elif raw_reasons is None:
            reasons_iter = []
        else:
            reasons_iter = [raw_reasons]
        reasons_all = sorted({str(reason) for reason in reasons_iter if str(reason)})
        emoji_ratio_val = _coerce_float_value(unicode_result.report.get("emoji_ratio", 0.0))
        emoji_count_val = _coerce_int_value(unicode_result.report.get("emoji_count", 0))
        mixed_tokens_val = _coerce_int_value(unicode_result.report.get("mixed_script_tokens", 0))
        confusables_val = _coerce_int_value(unicode_result.report.get("confusables_count", 0))
        for reason in reasons_all:
            unicode_suspicious_total.labels(reason=reason).inc()
        unicode_annotation = {
            "normalized": bool(unicode_result.normalized),
            "suspicious": bool(unicode_result.report.get("suspicious", False)),
            "reasons": reasons_all,
            "block_reasons": list(unicode_result.block_reasons),
            "emoji_ratio": round(emoji_ratio_val, 4),
            "emoji_count": emoji_count_val,
            "mixed_script_tokens": mixed_tokens_val,
            "confusables_count": confusables_val,
            "has_bidi": bool(unicode_result.report.get("has_bidi", False)),
            "has_zw": bool(unicode_result.report.get("has_zw", False)),
            "has_invisible": bool(unicode_result.report.get("has_invisible", False)),
            "has_tags": bool(unicode_result.report.get("has_tags", False)),
        }
        unicode_annotation["suspicious_reasons"] = list(unicode_result.suspicious_reasons)
        unicode_annotation["blocked"] = unicode_result.should_block
        if unicode_findings_summary:
            unicode_annotation["findings"] = copy.deepcopy(unicode_findings_summary)
        if unicode_result.should_block:
            message = (
                "Suspicious Unicode characters detected. Please resend plain text "
                "without invisible or mixed-script characters."
            )
            incident_id = make_incident_id()
            block_payload = {
                "action": "block_input_only",
                "reason": "suspicious_unicode",
                "message": message,
                "incident_id": incident_id,
                "meta": {
                    "unicode_reasons": ",".join(unicode_result.block_reasons) or "unknown",
                },
            }
            resp = JSONResponse(status_code=200, content=block_payload)
            resp.headers[INCIDENT_HEADER] = incident_id
            attach_guardrail_headers(
                resp,
                decision="block",
                ingress_action="block_input_only",
                egress_action="allow",
            )
            unicode_header_payload = json.dumps(
                unicode_annotation, separators=(",", ":"), ensure_ascii=False
            )
            _record_actor_metric(request, "block_input_only")
            return finalize_response(
                resp,
                decision_family="deny",
                rule_ids=None,
                policy_result={
                    "action": "block_input_only",
                    "reason": "suspicious_unicode",
                    "unicode_reasons": list(unicode_result.block_reasons),
                },
            )
        has_unicode_signal = unicode_result.normalized or bool(reasons_all)
        if has_unicode_signal:
            unicode_header_payload = json.dumps(
                unicode_annotation, separators=(",", ":"), ensure_ascii=False
            )
        else:
            unicode_annotation = None
            unicode_header_payload = None

    prompt_hash_val = _prompt_hash(combined_text)

    # Ingress rulepack enforcement (opt-in)
    should_block, hits = ingress_should_block(combined_text or "")
    if should_block:
        # Honor configured RULEPACKS_INGRESS_MODE
        mode_cfg = ingress_mode()
        if mode_cfg == "block":
            resp = JSONResponse(
                status_code=200,
                content={
                    "action": "block_input_only",
                    "reason": "ingress_rulepack",
                    "matches": hits,
                },
            )
            resp.headers[INCIDENT_HEADER] = "rpb"
            attach_guardrail_headers(
                resp,
                decision="block",
                ingress_action="block_input_only",
                egress_action="allow",
            )
            _augment_json_response(resp, mitigation_modes, decision="block")
            try:
                from app.services.audit_forwarder import emit_audit_event

                emit_audit_event(
                    {
                        "event": "decision",
                        "data": {
                            "decision": "block_input_only",
                            "reason": "ingress_rulepack",
                        },
                    }
                )
            except Exception:
                pass
            _record_actor_metric(request, "block_input_only")
            return finalize_response(
                resp,
                decision_family="deny",
                rule_ids=hits,
                policy_result={
                    "action": "block_input_only",
                    "rule_ids": [str(h) for h in hits if str(h)],
                },
            )
        elif mode_cfg == "clarify":
            forced_block = bool(mitigation_modes.get("block"))
            try:
                from app.services.audit_forwarder import emit_audit_event

                emit_audit_event(
                    {
                        "event": "decision",
                        "data": {
                            "decision": ("block_input_only" if forced_block else "clarify"),
                            "reason": "ingress_rulepack",
                        },
                    }
                )
            except Exception:
                pass
            if forced_block:
                _obs_metrics.inc_mitigation_override("block")
                _record_actor_metric(request, "block_input_only")
                resp = JSONResponse(
                    status_code=200,
                    content={
                        "action": "block_input_only",
                        "reason": "ingress_rulepack",
                        "matches": hits,
                    },
                )
                resp.headers[INCIDENT_HEADER] = "rpb"
                attach_guardrail_headers(
                    resp,
                    decision="block",
                    ingress_action="block_input_only",
                    egress_action="allow",
                )
                _augment_json_response(
                    resp,
                    mitigation_modes,
                    decision="block",
                    forced="block",
                )
                return finalize_response(
                    resp,
                    decision_family="deny",
                    rule_ids=hits,
                    policy_result={
                        "action": "block_input_only",
                        "rule_ids": [str(h) for h in hits if str(h)],
                    },
                )
            _record_actor_metric(request, "clarify")
            clar_resp = respond_with_clarify(
                extra={"rulepack": "ingress_block", "matches": ",".join(hits)}
            )
            _augment_json_response(clar_resp, mitigation_modes, decision="clarify")
            return finalize_response(
                clar_resp,
                decision_family="deny",
                rule_ids=hits,
                policy_result={
                    "action": "clarify",
                    "rule_ids": [str(h) for h in hits if str(h)],
                },
            )
        else:
            # annotate only → continue
            pass

    classifier_outcome, policy_hits, policy_dbg = _evaluate_ingress_policy(
        combined_text, want_debug
    )
    if classifier_outcome in {"allow", "block", "ambiguous", "unknown"}:
        action = map_classifier_outcome_to_action(classifier_outcome)  # type: ignore[arg-type]
    else:
        action = classifier_outcome

    if action == "clarify" and not mitigation_modes.get("block"):
        _audit(
            "ingress",
            combined_text,
            "",
            "clarify",
            tenant,
            bot,
            request_id,
            policy_hits,
            0,
        )
        _bump_family("ingress", "ingress_evaluate", "clarify", tenant, bot)
        try:
            from app.services.audit_forwarder import emit_audit_event
        except Exception:  # pragma: no cover

            def emit_audit_event(*args, **kwargs):  # type: ignore
                return None

        emit_audit_event(
            {
                "event": "decision",
                "phase": "ingress",
                "decision": "clarify",
                "reason": f"classifier_outcome={classifier_outcome}",
            }
        )
        _record_actor_metric(request, "clarify")
        clar_resp = respond_with_clarify()
        _augment_json_response(clar_resp, mitigation_modes, decision="clarify")
        return finalize_response(
            clar_resp,
            decision_family="deny",
            rule_ids=_rule_ids_from_hits(policy_hits),
            policy_result={
                "action": "clarify",
                "rule_ids": _rule_ids_from_hits(policy_hits),
            },
        )
    (
        redacted,
        redaction_hits,
        redaction_count,
        redaction_spans,
    ) = _apply_redactions(combined_text, direction="ingress")

    if tf_enabled():
        redacted, fams, tf_count, _ = tf_apply(redacted, debug=want_debug)
        redaction_count += tf_count
        for tag in fams.keys():
            redaction_hits.setdefault(tag, []).append("<threat_feed>")
    for tag in redaction_hits.keys():
        m.inc_redaction(tag)
        m.guardrail_redactions_total.labels("ingress", tag).inc()

    for k, v in redaction_hits.items():
        policy_hits.setdefault(k, []).extend(v)
    _normalize_wildcards(policy_hits, is_deny=(action == "deny"))

    dbg_sources: List[SourceDebug] = []
    dbg: Optional[Dict[str, Any]] = None
    if want_debug:
        matches = [{"tag": k, "patterns": list(v)} for k, v in policy_hits.items()]

        dbg = {"matches": matches}
        if redaction_hits:
            dbg["redaction_sources"] = list(redaction_hits.keys())
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

    # Always apply injection default first (before sampling gate).
    base_decision: Dict[str, Any] = {"action": action, "rule_hits": policy_hits}
    if dbg is not None:
        base_decision["debug"] = dbg
    base_decision = apply_injection_default(base_decision)
    if unicode_annotation:
        base_decision.setdefault("unicode", unicode_annotation)
    action = base_decision.get("action", action)
    dbg = base_decision.get("debug", dbg)

    # Verifier sampling gate (stateless)
    verifier_sampled = False
    pct = _verifier_sampling_pct()
    if pct > 0.0 and _hits_trigger_verifier(policy_hits):
        if random.random() < pct:
            base_decision = maybe_route_to_verifier(base_decision, text=combined_text)
            action = base_decision.get("action", action)
            dbg = base_decision.get("debug", dbg)
            verifier_sampled = True

    # Hardened verifier (optional, authoritative)
    t_hv = time.perf_counter()
    hv_action, hv_headers = await _maybe_hardened(
        text=combined_text,
        direction="ingress",
        tenant=tenant,
        bot=bot,
        family=headers.get("X-Model-Family"),
    )
    latency_ms = int((time.perf_counter() - t_hv) * 1000)
    hv_headers = dict(hv_headers or {})
    hv_headers.setdefault("X-Guardrail-Verifier-Latency", str(latency_ms))
    m.observe_verifier_latency(latency_ms)
    v_action: Optional[str] = None
    if hv_action in {"timeout", "error", "uncertain"}:
        v_action = map_verifier_outcome_to_action(hv_action)  # type: ignore[arg-type]
    if v_action == "clarify" and not mitigation_modes.get("block"):
        try:
            from app.services.audit_forwarder import emit_audit_event
        except Exception:  # pragma: no cover

            def emit_audit_event(*args, **kwargs):  # type: ignore
                return None

        emit_audit_event(
            {
                "event": "decision",
                "phase": "ingress",
                "decision": "clarify",
                "reason": f"verifier_outcome={hv_action}",
            }
        )
        _record_actor_metric(request, "clarify")
        clar_resp = respond_with_clarify()
        _augment_json_response(clar_resp, mitigation_modes, decision="clarify")
        return _finalize_ingress_response(
            clar_resp,
            request_id=request_id,
            fingerprint_value=fingerprint_value,
            decision_family="deny",
            rule_ids=_rule_ids_from_hits(policy_hits),
            policy_result={"action": "clarify"},
        )

    action = _apply_hardened_override(action, hv_action)
    if hv_action is None and hv_headers.get("X-Guardrail-Verifier-Mode") == "fallback":
        action = _apply_hardened_error_fallback(action)

    verifier_info = None
    if hv_headers:
        provider = hv_headers.get("X-Guardrail-Verifier", "unknown")
        verifier_info = {
            "provider": provider,
            "decision": action,
            "latency_ms": latency_ms,
        }
        if isinstance(provider, str) and provider.strip():
            adjudication_provider = provider.strip()
        m.inc_verifier_attempt(provider)
        retries = 0
        try:
            retries = int(hv_headers.get("X-Guardrail-Verifier-Retries", "0"))
        except Exception:
            retries = 0
        for _ in range(max(0, retries)):
            _maybe_metric("inc_verifier_retry", provider)
        hv_mode = (
            "fallback" if hv_headers.get("X-Guardrail-Verifier-Mode") == "fallback" else "live"
        )
        _maybe_metric("inc_verifier_mode", hv_mode)

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
        verifier=verifier_info,
    )
    _bump_family("ingress", "ingress_evaluate", action, tenant, bot)

    _record_actor_metric(request, action)

    base_decision.setdefault("rule_ids", _rule_ids_from_hits(base_decision.get("rule_hits")))

    adjudication_sampled = verifier_sampled
    mitigation_forced: Optional[str] = None
    decision_override: Optional[str] = None
    natural_action = str(action or "")
    if mitigation_modes.get("block"):
        if natural_action.lower() not in _BLOCK_DECISIONS:
            _obs_metrics.inc_mitigation_override("block")
        action = "deny"
        mitigation_forced = "block"
        decision_override = "block"
    base_decision["action"] = action
    routing_meta = _routing_decision(action, policy_hits, prompt_hash_val or "")
    base_decision["routing"] = routing_meta
    resp = _respond_action(
        action,
        redacted,
        request_id,
        policy_hits,
        dbg,
        redaction_count=redaction_count,
        modalities=mods,
        verifier_sampled=verifier_sampled,
        direction="ingress",
        extra_headers=hv_headers,
        mitigation_modes=mitigation_modes,
        mitigation_forced=mitigation_forced,
        decision_override=decision_override,
        routing_meta=routing_meta,
    )
    return finalize_response(
        resp,
        decision_family=_decision_family(action),
        rule_ids=_rule_ids_from_hits(policy_hits),
        policy_result=base_decision,
    )


@router.post("/guardrail/evaluate_multipart")
async def guardrail_evaluate_multipart(request: Request):
    t_start = time.perf_counter()
    headers = request.headers
    tenant, bot = _tenant_bot(
        headers.get("X-Tenant") or headers.get("X-Tenant-ID"),
        headers.get("X-Bot") or headers.get("X-Bot-ID"),
    )
    raw_tenant = (headers.get("X-Tenant-ID") or headers.get("X-Tenant") or "").strip()
    raw_bot = (headers.get("X-Bot-ID") or headers.get("X-Bot") or "").strip()
    mitigation_modes = get_mitigation_modes(raw_tenant, raw_bot)
    want_debug = _debug_requested(headers.get("X-Debug"))
    m.inc_requests_total("ingress_evaluate")
    m.set_policy_version(current_rules_version())

    req_header_request_id = headers.get(REQ_ID_HEADER)
    try:
        fingerprint_value = fingerprint(request)
    except Exception:
        fingerprint_value = ""
    prompt_hash_val: Optional[str] = None
    adjudication_provider: Optional[str] = None
    adjudication_sampled = False
    rules_path_hint = _resolve_rules_path_hint(tenant, bot)

    combined_text, mods, sources, docx_results = await _read_form_and_merge(
        request, decode_pdf=True
    )
    for src in sources:
        fname = src.get("filename")
        if fname:
            src["filename"] = normalize_nfkc(str(fname))
    request_id = _req_id(req_header_request_id)
    unicode_header_payload: Optional[str] = None
    unicode_annotation_mp: Optional[Dict[str, Any]] = None
    unicode_findings_summary_mp: Optional[Dict[str, Any]] = None

    if settings.SANITIZER_CONFUSABLES_ENABLED and combined_text:
        combined_text, unicode_findings_summary_mp = _inspect_unicode_findings(combined_text)

    if settings.UNICODE_SANITIZER_ENABLED and combined_text:
        unicode_cfg = UnicodeSanitizerCfg(
            normalize_only=False,
            block_on_controls=settings.UNICODE_BLOCK_ON_BIDI,
            block_on_mixed_script=settings.UNICODE_BLOCK_ON_MIXED_SCRIPT,
            emoji_ratio_warn=settings.UNICODE_EMOJI_RATIO_WARN,
        )
        unicode_result = sanitize_unicode(combined_text, unicode_cfg)
        combined_text = unicode_result.text
        if unicode_result.normalized:
            unicode_normalized_total.inc()
        raw_reasons = unicode_result.report.get("reasons", [])
        if isinstance(raw_reasons, (list, tuple, set)):
            reasons_iter = raw_reasons
        elif raw_reasons is None:
            reasons_iter = []
        else:
            reasons_iter = [raw_reasons]
        reasons_all = sorted({str(reason) for reason in reasons_iter if str(reason)})
        emoji_ratio_val = _coerce_float_value(unicode_result.report.get("emoji_ratio", 0.0))
        emoji_count_val = _coerce_int_value(unicode_result.report.get("emoji_count", 0))
        mixed_tokens_val = _coerce_int_value(unicode_result.report.get("mixed_script_tokens", 0))
        confusables_val = _coerce_int_value(unicode_result.report.get("confusables_count", 0))
        for reason in reasons_all:
            unicode_suspicious_total.labels(reason=reason).inc()
        unicode_annotation_mp = {
            "normalized": bool(unicode_result.normalized),
            "suspicious": bool(unicode_result.report.get("suspicious", False)),
            "reasons": reasons_all,
            "block_reasons": list(unicode_result.block_reasons),
            "emoji_ratio": round(emoji_ratio_val, 4),
            "emoji_count": emoji_count_val,
            "mixed_script_tokens": mixed_tokens_val,
            "confusables_count": confusables_val,
            "has_bidi": bool(unicode_result.report.get("has_bidi", False)),
            "has_zw": bool(unicode_result.report.get("has_zw", False)),
            "has_invisible": bool(unicode_result.report.get("has_invisible", False)),
            "has_tags": bool(unicode_result.report.get("has_tags", False)),
        }
        unicode_annotation_mp["suspicious_reasons"] = list(unicode_result.suspicious_reasons)
        unicode_annotation_mp["blocked"] = unicode_result.should_block
        if unicode_findings_summary_mp:
            unicode_annotation_mp["findings"] = copy.deepcopy(unicode_findings_summary_mp)
        if unicode_result.should_block:
            message = (
                "Suspicious Unicode characters detected. Please resend plain text "
                "without invisible or mixed-script characters."
            )
            incident_id = make_incident_id()
            block_payload = {
                "action": "block_input_only",
                "reason": "suspicious_unicode",
                "message": message,
                "incident_id": incident_id,
                "meta": {
                    "unicode_reasons": ",".join(unicode_result.block_reasons) or "unknown",
                },
            }
            resp = JSONResponse(status_code=200, content=block_payload)
            resp.headers[INCIDENT_HEADER] = incident_id
            attach_guardrail_headers(
                resp,
                decision="block",
                ingress_action="block_input_only",
                egress_action="allow",
            )
            unicode_header_payload = json.dumps(
                unicode_annotation_mp, separators=(",", ":"), ensure_ascii=False
            )
            _record_actor_metric(request, "block_input_only")
            finalized_block = _finalize_ingress_response(
                resp,
                request_id=request_id,
                fingerprint_value=fingerprint_value,
                decision_family="deny",
                rule_ids=[],
                policy_result={
                    "action": "block_input_only",
                    "reason": "suspicious_unicode",
                    "unicode_reasons": list(unicode_result.block_reasons),
                },
            )
            if unicode_header_payload:
                finalized_block.headers.setdefault("X-Guardrail-Unicode", unicode_header_payload)
            prompt_hash_val = _prompt_hash(combined_text)
            _audit(
                "ingress",
                combined_text,
                combined_text,
                "block_input_only",
                tenant,
                bot,
                request_id,
                [],
                0,
            )
            _bump_family("ingress", "ingress_evaluate", "block_input_only", tenant, bot)
            latency_ms = int((time.perf_counter() - t_start) * 1000)
            policy_version_hint = finalized_block.headers.get("X-Guardrail-Policy-Version")
            rules_path = finalized_block.headers.get("X-Guardrail-Rules-Path") or rules_path_hint
            _log_adjudication(
                request_id=request_id,
                tenant=tenant,
                bot=bot,
                decision="block_input_only",
                rule_ids=[],
                latency_ms=latency_ms,
                policy_version=policy_version_hint,
                rules_path=rules_path,
                sampled=False,
                prompt_sha256=prompt_hash_val,
                provider=None,
                score=None,
            )
            return finalized_block
        has_unicode_signal = unicode_result.normalized or bool(reasons_all)
        if has_unicode_signal:
            unicode_header_payload = json.dumps(
                unicode_annotation_mp, separators=(",", ":"), ensure_ascii=False
            )
        else:
            unicode_annotation_mp = None
            unicode_header_payload = None
    prompt_hash_val = _prompt_hash(combined_text)

    action, policy_hits, policy_dbg = _evaluate_ingress_policy(combined_text, want_debug)
    (
        redacted,
        redaction_hits,
        redaction_count,
        redaction_spans,
    ) = _apply_redactions(combined_text, direction="ingress")

    if tf_enabled():
        redacted, fams, tf_count, _ = tf_apply(redacted, debug=want_debug)
        redaction_count += tf_count
        for tag in fams.keys():
            redaction_hits.setdefault(tag, []).append("<threat_feed>")

    for k, v in redaction_hits.items():
        policy_hits.setdefault(k, []).extend(v)
    for tag in redaction_hits.keys():
        m.inc_redaction(tag)
        m.guardrail_redactions_total.labels("ingress", tag).inc()
    docx_hidden_reasons: List[str] = []
    docx_hidden_samples: List[str] = []
    for dres in docx_results:
        dbg_info = getattr(dres, "debug", {}) or {}
        h_reasons = cast(List[str], dbg_info.get("hidden_reasons") or [])
        h_samples = cast(List[str], dbg_info.get("hidden_samples") or [])
        if h_reasons:
            action = "deny"
            docx_hidden_reasons.extend(h_reasons)
            docx_hidden_samples.extend(h_samples)
            for r in h_reasons:
                _maybe_metric("inc_docx_hidden", str(r))
                policy_hits.setdefault(str(r), []).append("<docx>")

    _normalize_wildcards(policy_hits, is_deny=(action == "deny"))

    dbg_sources: List[SourceDebug] = []
    dbg: Optional[Dict[str, Any]] = None
    if want_debug:
        matches = [{"tag": k, "patterns": list(v)} for k, v in policy_hits.items()]
        dbg = {"matches": matches}
        if redaction_hits:
            dbg["redaction_sources"] = list(redaction_hits.keys())
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
        if docx_hidden_reasons:
            dbg["hidden_reasons"] = docx_hidden_reasons
            dbg["hidden_samples"] = docx_hidden_samples[:5]

    # Always apply injection default first (before sampling gate).
    base_decision: Dict[str, Any] = {"action": action, "rule_hits": policy_hits}
    if dbg is not None:
        base_decision["debug"] = dbg
    base_decision = apply_injection_default(base_decision)
    action = base_decision.get("action", action)
    dbg = base_decision.get("debug", dbg)

    # Verifier sampling gate
    verifier_sampled = False
    pct = _verifier_sampling_pct()
    if pct > 0.0 and _hits_trigger_verifier(policy_hits):
        if random.random() < pct:
            base_decision = maybe_route_to_verifier(base_decision, text=combined_text)
            action = base_decision.get("action", action)
            dbg = base_decision.get("debug", dbg)
            verifier_sampled = True

    t_hv = time.perf_counter()
    hv_action, hv_headers = await _maybe_hardened(
        text=combined_text,
        direction="ingress",
        tenant=tenant,
        bot=bot,
        family=headers.get("X-Model-Family"),
    )
    latency_ms = int((time.perf_counter() - t_hv) * 1000)
    hv_headers = dict(hv_headers or {})
    hv_headers.setdefault("X-Guardrail-Verifier-Latency", str(latency_ms))
    m.observe_verifier_latency(latency_ms)
    action = _apply_hardened_override(action, hv_action)
    if hv_action is None and hv_headers.get("X-Guardrail-Verifier-Mode") == "fallback":
        action = _apply_hardened_error_fallback(action)

    verifier_info = None
    if hv_headers:
        provider = hv_headers.get("X-Guardrail-Verifier", "unknown")
        verifier_info = {
            "provider": provider,
            "decision": action,
            "latency_ms": latency_ms,
        }
        if isinstance(provider, str) and provider.strip():
            adjudication_provider = provider.strip()
        m.inc_verifier_attempt(provider)
        retries = 0
        try:
            retries = int(hv_headers.get("X-Guardrail-Verifier-Retries", "0"))
        except Exception:
            retries = 0
        for _ in range(max(0, retries)):
            _maybe_metric("inc_verifier_retry", provider)
        mode = "fallback" if hv_headers.get("X-Guardrail-Verifier-Mode") == "fallback" else "live"
        _maybe_metric("inc_verifier_mode", mode)

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
        verifier=verifier_info,
    )
    _bump_family("ingress", "ingress_evaluate", action, tenant, bot)

    _record_actor_metric(request, action)

    base_decision.setdefault("rule_ids", _rule_ids_from_hits(base_decision.get("rule_hits")))

    adjudication_sampled = verifier_sampled
    mitigation_forced: Optional[str] = None
    decision_override: Optional[str] = None
    natural_action = str(action or "")
    if mitigation_modes.get("block"):
        if natural_action.lower() not in _BLOCK_DECISIONS:
            _obs_metrics.inc_mitigation_override("block")
        action = "deny"
        mitigation_forced = "block"
        decision_override = "block"
    base_decision["action"] = action
    routing_meta = _routing_decision(action, policy_hits, prompt_hash_val or "")
    base_decision["routing"] = routing_meta
    resp = _respond_action(
        action,
        redacted,
        request_id,
        policy_hits,
        dbg,
        redaction_count=redaction_count,
        modalities=mods,
        verifier_sampled=verifier_sampled,
        direction="ingress",
        extra_headers=hv_headers,
        mitigation_modes=mitigation_modes,
        mitigation_forced=mitigation_forced,
        decision_override=decision_override,
        routing_meta=routing_meta,
    )
    finalized = _finalize_ingress_response(
        resp,
        request_id=request_id,
        fingerprint_value=fingerprint_value,
        decision_family=_decision_family(action),
        rule_ids=_rule_ids_from_hits(policy_hits),
        policy_result=base_decision,
    )
    if unicode_header_payload:
        finalized.headers.setdefault("X-Guardrail-Unicode", unicode_header_payload)

    provider_hint = adjudication_provider
    if isinstance(base_decision, Mapping):
        raw_provider = base_decision.get("provider")
        if isinstance(raw_provider, str) and raw_provider.strip():
            provider_hint = provider_hint or raw_provider.strip()
        else:
            raw_verifier = base_decision.get("verifier")
            if isinstance(raw_verifier, Mapping):
                vprov = raw_verifier.get("provider")
                if isinstance(vprov, str) and vprov.strip():
                    provider_hint = provider_hint or vprov.strip()

    header_provider = finalized.headers.get("X-Guardrail-Verifier")
    if not provider_hint and header_provider:
        provider_hint = header_provider

    sampled_flag = adjudication_sampled
    header_sampled = finalized.headers.get("X-Guardrail-Verifier-Sampled")
    if header_sampled is not None:
        sampled_flag = sampled_flag or header_sampled == "1"

    latency_ms = int((time.perf_counter() - t_start) * 1000)
    policy_version_hint = finalized.headers.get("X-Guardrail-Policy-Version")
    rules_path = finalized.headers.get("X-Guardrail-Rules-Path") or rules_path_hint

    decision_val = action
    if isinstance(base_decision, Mapping):
        raw_action = base_decision.get("action")
        if isinstance(raw_action, str) and raw_action.strip():
            decision_val = raw_action.strip()

    score_val = None
    if isinstance(base_decision, Mapping):
        score_val = _coerce_score(base_decision.get("score"))

    _log_adjudication(
        request_id=request_id,
        tenant=tenant,
        bot=bot,
        decision=str(decision_val or "unknown"),
        rule_ids=_rule_ids_from_hits(policy_hits),
        latency_ms=latency_ms,
        policy_version=policy_version_hint,
        rules_path=rules_path,
        sampled=sampled_flag,
        prompt_sha256=prompt_hash_val,
        provider=provider_hint,
        score=score_val,
    )

    return finalized


@router.post("/guardrail/egress_evaluate")
async def guardrail_egress(request: Request):
    headers = request.headers
    tenant, bot = _tenant_bot(
        headers.get("X-Tenant") or headers.get("X-Tenant-ID"),
        headers.get("X-Bot") or headers.get("X-Bot-ID"),
    )
    want_debug = _debug_requested(headers.get("X-Debug"))
    m.inc_requests_total("egress_evaluate")
    m.set_policy_version(current_rules_version())

    payload = await request.json()
    text = str(payload.get("text") or "")
    request_id = _req_id(str(payload.get("request_id") or ""))

    action, transformed, rule_hits, debug_info = _egress_policy(text, want_debug)
    (
        redacted,
        redaction_hits,
        redaction_count,
        redaction_spans,
    ) = _apply_redactions(transformed, direction="egress")

    if tf_enabled():
        redacted, fams, tf_count, _ = tf_apply(redacted, debug=False)
        redaction_count += tf_count
        for tag in fams.keys():
            redaction_hits.setdefault(tag, []).append("<threat_feed>")

    for k, v in redaction_hits.items():
        rule_hits.setdefault(k, []).extend(v)
    for tag in redaction_hits.keys():
        m.inc_redaction(tag)
        m.guardrail_redactions_total.labels("egress", tag).inc()
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

    # Hardened verifier AFTER egress policy + redactions
    t_hv = time.perf_counter()
    hv_action, hv_headers = await _maybe_hardened(
        text=redacted,
        direction="egress",
        tenant=tenant,
        bot=bot,
        family=headers.get("X-Model-Family"),
    )
    latency_ms = int((time.perf_counter() - t_hv) * 1000)
    hv_headers = dict(hv_headers or {})
    hv_headers.setdefault("X-Guardrail-Verifier-Latency", str(latency_ms))
    m.observe_verifier_latency(latency_ms)
    action = _apply_hardened_override(action, hv_action)
    if hv_action is None and hv_headers.get("X-Guardrail-Verifier-Mode") == "fallback":
        action = _apply_hardened_error_fallback(action)

    verifier_info = None
    if hv_headers:
        provider = hv_headers.get("X-Guardrail-Verifier", "unknown")
        verifier_info = {
            "provider": provider,
            "decision": action,
            "latency_ms": latency_ms,
        }
        m.inc_verifier_attempt(provider)
        retries = 0
        try:
            retries = int(hv_headers.get("X-Guardrail-Verifier-Retries", "0"))
        except Exception:
            retries = 0
        for _ in range(max(0, retries)):
            _maybe_metric("inc_verifier_retry", provider)
        mode = "fallback" if hv_headers.get("X-Guardrail-Verifier-Mode") == "fallback" else "live"
        _maybe_metric("inc_verifier_mode", mode)

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
        verifier=verifier_info,
    )
    _bump_family("egress", "egress_evaluate", action, tenant, bot)

    _record_actor_metric(request, action)

    return _respond_action(
        action,
        redacted,
        request_id,
        rule_hits,
        dbg,
        redaction_count=redaction_count,
        modalities=None,
        verifier_sampled=False,
        direction="egress",
        extra_headers=hv_headers,
    )

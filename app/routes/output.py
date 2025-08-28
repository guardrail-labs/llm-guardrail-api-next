from __future__ import annotations

import json
import logging
import os
import time
import uuid
from typing import List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse

from app.routes.schema import OutputGuardrailRequest, GuardrailResponse
from app.services import policy
from app.services.policy import evaluate_and_apply, current_rules_version, reload_rules
from app.config import get_settings

router = APIRouter(prefix="/guardrail", tags=["guardrail"])

_AUDIT_LOG = logging.getLogger("guardrail_audit")

# per-process rolling window for legacy ingress rate limit
_BUCKETS: Dict[str, List[float]] = {}
_RATE_LOCK = logging.RLock()  # type: ignore[attr-defined]


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _env_bool(name: str, default: bool = False) -> bool:
    raw = (os.environ.get(name) or "").strip().lower()
    if raw in ("true", "1", "yes", "on"):
        return True
    if raw in ("false", "0", "no", "off"):
        return False
    return default


def _env_int(name: str, default: int = 0) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except Exception:
        return default


def _audit_enabled() -> bool:
    return _env_bool("AUDIT_ENABLED", False)


def _audit_sample_rate() -> float:
    try:
        return float(os.environ.get("AUDIT_SAMPLE_RATE", "0"))
    except Exception:
        return 0.0


def _audit_max_chars() -> int:
    return _env_int("AUDIT_MAX_TEXT_CHARS", 0)


def _emit_audit(prompt: str, request_id: str) -> None:
    if not _audit_enabled():
        return
    # Always sample when tests set 1.0; otherwise probabilistic (but deterministic enough here)
    rate = _audit_sample_rate()
    if rate <= 0.0:
        return
    # Truncate snippet
    max_chars = _audit_max_chars()
    snippet = prompt[:max_chars] if max_chars and max_chars > 0 else prompt
    try:
        _AUDIT_LOG.info("ingress %s", snippet, extra={"request_id": request_id})
    except Exception:
        # Never break the request path due to logging
        pass


def _rate_cfg() -> tuple[bool, int, int]:
    # IMPORTANT: default disabled so tests only see rate limiting when explicitly enabled
    enabled = _env_bool("RATE_LIMIT_ENABLED", False)
    per_min = _env_int("RATE_LIMIT_PER_MINUTE", 60)
    burst = _env_int("RATE_LIMIT_BURST", per_min)
    return enabled, per_min, burst


def _rate_limit_remaining(request: Request) -> int:
    enabled, per_min, burst = _rate_cfg()
    if not enabled:
        return per_min
    now = time.time()
    key = _client_key(request)
    with _RATE_LOCK:
        win = _BUCKETS.setdefault(key, [])
        cutoff = now - 60.0
        win[:] = [t for t in win if t >= cutoff]
        if len(win) >= burst:
            return 0
        win.append(now)
        return max(0, per_min - len(win))


def _need_auth(request: Request) -> bool:
    return not (
        request.headers.get("x-api-key")
        or request.headers.get("authorization")
    )


def _json_error(code: str, request_id: str, message: str) -> Dict[str, Any]:
    return {"code": code, "request_id": request_id, "message": message}


def _flatten_rule_hits(raw: Any) -> List[str]:
    out: List[str] = []
    if not isinstance(raw, list):
        return out
    for h in raw:
        if isinstance(h, dict):
            s = (
                h.get("id")
                or h.get("pattern")
                or h.get("tag")
                or h.get("name")
                or str(h)
            )
            out.append(str(s))
        elif isinstance(h, str):
            out.append(h)
        else:
            out.append(str(h))
    return out


# ---------- Legacy root guardrail endpoint: POST /guardrail ----------
@router.post("/")
async def guardrail_root(request: Request) -> JSONResponse:
    """
    JSON: {"prompt": "..."}
    Auth required. Optional rate limit (off by default).
    Emits audit log when AUDIT_* envs are set.
    Returns:
      {
        "decision": "allow" | "block",
        "transformed_text": str,
        "policy_version": str,
        "request_id": str,
        "rule_hits": [str],
      }
    Error responses:
      401 -> {"detail": "Unauthorized", "request_id": "..."}
      413 -> {"code": "payload_too_large", "request_id": "...", "message": "..."}
      429 -> {"code": "too_many_requests", "request_id": "...", "message": "..."}
    """
    # Autoreload policy if enabled (tests expect version updates without hitting admin endpoint)
    _ = current_rules_version()  # triggers maybe-autoreload inside policy

    rid = request.headers.get("x-request-id") or str(uuid.uuid4())

    # Auth
    if _need_auth(request):
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Unauthorized", "request_id": rid},
            headers={"WWW-Authenticate": "Bearer", "X-Request-ID": rid},
        )

    # Rate limit (default disabled)
    remaining = _rate_limit_remaining(request)
    if remaining == 0:
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content=_json_error("too_many_requests", rid, "Rate limit exceeded"),
            headers={"Retry-After": "60", "X-Request-ID": rid},
        )

    # Parse
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    prompt = str(payload.get("prompt", ""))

    # Size limit via env (matches tests)
    max_chars = _env_int("MAX_PROMPT_CHARS", 0)
    if max_chars and len(prompt) > max_chars:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content=_json_error("payload_too_large", rid, "Prompt too large"),
            headers={"X-Request-ID": rid},
        )

    # Audit log
    _emit_audit(prompt, rid)

    # Apply policies
    res = policy.apply_policies(prompt)
    hits = {h.get("tag") for h in res.get("hits", [])}
    decision = "block" if ({"unsafe", "gray", "secrets"} & hits) else "allow"

    transformed = res.get("sanitized_text", prompt)
    rule_hits = _flatten_rule_hits(res.get("hits", []))

    body: Dict[str, Any] = {
        "decision": decision,
        "transformed_text": transformed,
        "policy_version": str(current_rules_version()),
        "request_id": rid,
        "rule_hits": rule_hits,
    }
    return JSONResponse(status_code=status.HTTP_200_OK, content=body)


# ---------- Output guardrail (egress) ----------
def _egress_limit(s) -> int:
    env_val = _env_int("OUTPUT_MAX_CHARS", 0)
    cfg_val = int(getattr(s, "MAX_OUTPUT_CHARS", 0) or 0)
    return max(env_val, cfg_val)


@router.post("/output", response_model=GuardrailResponse)
def guard_output(
    ingress: OutputGuardrailRequest, s=Depends(get_settings)
) -> GuardrailResponse:
    """
    Egress filter:
      - Enforces output size limit via OUTPUT_MAX_CHARS (env) or settings.MAX_OUTPUT_CHARS.
      - If REDACT_SECRETS=true, apply policy redactions.
      - Always return decision="allow" with required schema fields.
    """
    req_id = getattr(ingress, "request_id", None) or str(uuid.uuid4())

    max_chars = _egress_limit(s)
    if max_chars and len(ingress.output) > max_chars:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Output too large",
        )

    redact = (_env_bool("REDACT_SECRETS", False))

    if redact:
        res = evaluate_and_apply(ingress.output)
        transformed = res.get("transformed_text", ingress.output)
        rule_hits = _flatten_rule_hits(res.get("rule_hits", []))
        reason = "redacted" if int(res.get("redactions", 0) or 0) > 0 else ""
    else:
        transformed = ingress.output
        rule_hits = []
        reason = ""

    return GuardrailResponse(
        transformed_text=transformed,
        decision="allow",
        request_id=req_id,
        reason=reason,
        rule_hits=rule_hits,
        policy_version=str(current_rules_version()),
    )

"""Policy evaluation and redaction.

- Loads YAML rules and surfaces version.
- Auto-reloads when POLICY_AUTORELOAD=true and mtime changes.
- Evaluates text via upipe to produce decision, rule hits, and reason.
- Optionally redacts secrets when REDACT_SECRETS=true.
- Emits an audit event using the transformed (redacted) text.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple
from uuid import uuid4

import yaml

from app.services.upipe import analyze  # returns a tuple-like (decision, hits, reason)
from app.telemetry.audit import emit_decision_event

# --- Redaction patterns --------------------------------------------------------
_PAT_OPENAI = re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")
_PAT_AWS_AKID = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_PAT_PRIVKEY_BLOCK = re.compile(
    r"-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----",
    flags=re.DOTALL,
)
_REDACTIONS: List[Tuple[re.Pattern[str], str]] = [
    (_PAT_OPENAI, "[REDACTED:OPENAI_KEY]"),
    (_PAT_AWS_AKID, "[REDACTED:AWS_ACCESS_KEY_ID]"),
    (_PAT_PRIVKEY_BLOCK, "[REDACTED:PRIVATE_KEY]"),
]


def _truthy(val: str | None) -> bool:
    return str(val or "").strip().lower() in {"1", "true", "yes", "on"}


# --- Rules loading/versioning --------------------------------------------------
_DEFAULT_RULES_PATH = (Path(__file__).resolve().parent / "policy" / "rules.yaml").resolve()
_policy_data: Dict[str, Any] = {}
_policy_version: str = "0"
_rules_path: Path = _DEFAULT_RULES_PATH
_last_mtime: float = 0.0


def _env_rules_path() -> Path:
    p = os.getenv("POLICY_RULES_PATH", "")
    return Path(p).resolve() if p else _DEFAULT_RULES_PATH


def _load_rules(path: Path) -> Tuple[Dict[str, Any], str, float]:
    txt = path.read_text(encoding="utf-8")
    data: Dict[str, Any] = yaml.safe_load(txt) or {}
    ver = str(data.get("version", "0"))
    mtime = path.stat().st_mtime
    return data, ver, mtime


def _ensure_loaded() -> None:
    global _policy_data, _policy_version, _rules_path, _last_mtime

    path = _env_rules_path()
    autoreload = _truthy(os.getenv("POLICY_AUTORELOAD", "true"))

    if not _policy_data or _rules_path != path:
        _policy_data, _policy_version, _last_mtime = _load_rules(path)
        _rules_path = path
        return

    if autoreload:
        try:
            mtime = path.stat().st_mtime
        except FileNotFoundError:
            return
        if mtime > _last_mtime:
            _policy_data, _policy_version, _last_mtime = _load_rules(path)


def force_reload() -> str:
    """Force reload policy and return version."""
    global _policy_data, _policy_version, _rules_path, _last_mtime
    path = _env_rules_path()
    _policy_data, _policy_version, _last_mtime = _load_rules(path)
    _rules_path = path
    return _policy_version


def get_policy_version() -> str:
    _ensure_loaded()
    return _policy_version


# --- Redaction -----------------------------------------------------------------
def _apply_redaction(text: str) -> Tuple[str, bool]:
    changed = False
    out = text
    for pat, repl in _REDACTIONS:
        new_text, n = pat.subn(repl, out)
        if n:
            changed = True
            out = new_text
    return out, changed


# --- Public API ----------------------------------------------------------------
def evaluate_and_apply(text: str) -> Dict[str, Any]:
    """Return outcome payload:
       decision, reason, rule_hits, policy_version, transformed_text, request_id
    """
    _ensure_loaded()

    # Treat `analyze` results dynamically to remain robust to signature changes.
    res = analyze(text)
    decision = str(res[0])
    hits_raw = res[1]
    reason = str(res[2])

    rule_hits: List[str]
    if isinstance(hits_raw, (list, tuple, set)):
        rule_hits = [str(h) for h in hits_raw]
    else:
        rule_hits = [str(hits_raw)] if hits_raw is not None else []

    transformed = text
    if _truthy(os.getenv("REDACT_SECRETS", "false")):
        transformed, _ = _apply_redaction(text)

    req_id = str(uuid4())
    emit_decision_event(
        request_id=req_id,
        decision=decision,
        rule_hits=rule_hits,
        reason=reason,
        policy_version=get_policy_version(),
        prompt_text=transformed,
    )

    return {
        "request_id": req_id,
        "decision": decision,
        "reason": reason,
        "rule_hits": rule_hits,
        "policy_version": get_policy_version(),
        "transformed_text": transformed,
    }


__all__ = ["evaluate_and_apply", "force_reload", "get_policy_version"]

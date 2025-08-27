"""Policy evaluation and redaction.

Responsibilities:
- Load the YAML rules file and surface its `version` string.
- Auto-reload rules when POLICY_AUTORELOAD=true and file mtime changes.
- Evaluate text via the upipe analyzer to produce a Decision, rule hits, and reason.
- Optionally redact secret-like substrings when REDACT_SECRETS=true.
- Emit an audit event using the transformed (possibly redacted) text.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple
from uuid import uuid4

import yaml

from app.services.upipe import Decision, analyze  # Decision is a str/Literal alias
from app.telemetry.audit import emit_decision_event

# --- Redaction patterns --------------------------------------------------------

# OpenAI-style key: sk- (20+ mixed alnum)
_PAT_OPENAI = re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")

# AWS Access Key ID: AKIA + 16 uppercase letters/numbers
_PAT_AWS_AKID = re.compile(r"\bAKIA[0-9A-Z]{16}\b")

# PRIVATE KEY block (match header ... footer, across text)
_PAT_PRIVKEY_BLOCK = re.compile(
    r"-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----",
    flags=re.DOTALL,
)

_REDACTIONS: List[Tuple[re.Pattern[str], str]] = [
    (_PAT_OPENAI, "[REDACTED:OPENAI_KEY]"),
    (_PAT_AWS_AKID, "[REDACTED:AWS_ACCESS_KEY_ID]"),
    (_PAT_PRIVKEY_BLOCK, "[REDACTED:PRIVATE_KEY]"),
]


def _is_truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


# --- Rules loading / versioning ------------------------------------------------

_DEFAULT_RULES_PATH = (
    Path(__file__).resolve().parent / "policy" / "rules.yaml"
).resolve()

_policy_data: Dict[str, Any] = {}
_policy_version: str = "0"
_rules_path: Path = _DEFAULT_RULES_PATH
_last_mtime: float = 0.0


def _current_rules_path() -> Path:
    env_path = os.getenv("POLICY_RULES_PATH", "")
    return Path(env_path).resolve() if env_path else _DEFAULT_RULES_PATH


def _load_rules(path: Path) -> Tuple[Dict[str, Any], str, float]:
    text = path.read_text(encoding="utf-8")
    data: Dict[str, Any] = yaml.safe_load(text) or {}
    version = str(data.get("version", "0"))
    mtime = path.stat().st_mtime
    return data, version, mtime


def _ensure_loaded() -> None:
    global _policy_data, _policy_version, _rules_path, _last_mtime

    path = _current_rules_path()
    autoreload = _is_truthy(os.getenv("POLICY_AUTORELOAD", "true"))

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
    """Force reload the policy rules from disk and return the new version."""
    global _policy_data, _policy_version, _rules_path, _last_mtime
    path = _current_rules_path()
    _policy_data, _policy_version, _last_mtime = _load_rules(path)
    _rules_path = path
    return _policy_version


def get_policy_version() -> str:
    _ensure_loaded()
    return _policy_version


# --- Redaction -----------------------------------------------------------------


def _apply_redaction(text: str) -> Tuple[str, bool]:
    """Apply redaction patterns; return (transformed_text, changed?)."""
    changed = False
    transformed = text
    for pat, repl in _REDACTIONS:
        new_text, n = pat.subn(repl, transformed)
        if n > 0:
            changed = True
            transformed = new_text
    return transformed, changed


# --- Public evaluation API -----------------------------------------------------


def evaluate_and_apply(text: str) -> Dict[str, Any]:
    """Evaluate user text against the policy and return outcome payload.

    Returns a dict with keys:
      - decision: "allow" | "block"
      - reason: str
      - rule_hits: List[str]
      - policy_version: str
      - transformed_text: str (possibly redacted, or original)
      - request_id: str (UUID generated here)
    """
    _ensure_loaded()

    # Analyze via the upipe detector.
    # decision: Decision (Literal["allow","block"]), rule_hits: List[str], reason: str
    decision, rule_hits, reason = analyze(text)

    # Redaction is optional (enabled by env).
    transformed = text
    if _is_truthy(os.getenv("REDACT_SECRETS", "false")):
        transformed, _ = _apply_redaction(text)

    # Emit audit using the transformed text so logs don’t leak secrets.
    req_id = str(uuid4())
    emit_decision_event(
        request_id=req_id,
        decision=str(decision),        # Decision is a str/Literal alias
        rule_hits=list(rule_hits),     # ensure Iterable[str]
        reason=str(reason),
        policy_version=get_policy_version(),
        prompt_text=transformed,
    )

    return {
        "request_id": req_id,
        "decision": str(decision),
        "reason": str(reason),
        "rule_hits": list(rule_hits),
        "policy_version": get_policy_version(),
        "transformed_text": transformed,
    }


__all__ = [
    "evaluate_and_apply",
    "force_reload",
    "get_policy_version",
]

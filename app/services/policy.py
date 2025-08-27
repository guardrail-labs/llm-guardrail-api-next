# app/services/policy.py
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, List, Tuple

import yaml

# ---- settings (defensive import with fallback) ------------------------------
try:
    # If your project provides app.settings.get_settings, use it.
    from app.settings import get_settings as _external_get_settings  # type: ignore[attr-defined]
except Exception:  # pragma: no cover - only hit in minimal test envs
    _external_get_settings = None  # type: ignore[assignment]


def get_settings() -> Any:
    """
    Return project settings if available; otherwise a minimal env-backed shim.
    The shim exposes attributes by looking up environment variables of
    the same uppercase name (returns None if not set).
    """
    if _external_get_settings is not None:
        return _external_get_settings()

    class _Shim:
        def __getattr__(self, name: str) -> Any:
            return os.environ.get(name)

    return _Shim()


# ---- telemetry --------------------------------------------------------------
from app.telemetry.audit import emit_decision_event  # type: ignore[import-not-found]


# -------------------------
# Rule loading & compilation
# -------------------------

_DEFAULT_RULES_YAML = """\
version: "3"

rules:
  - id: payload:encoded_blob
    description: Detect long base64-like blobs
    regex: '/^[A-Za-z0-9+/=]{128,}$/'
    decision: block

  - id: secret:openai_key
    description: OpenAI API key
    regex: '/sk-[A-Za-z0-9]{16,}/'
    decision: block

  - id: secret:aws_access_key_id
    description: AWS Access Key ID
    regex: '/AKIA[0-9A-Z]{16}/'
    decision: block

  - id: secret:private_key_block
    description: Private key PEM block markers
    regex: '/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----/'
    decision: block

  - id: payload:prompt_injection_phrase
    description: Common prompt-injection phrase
    regex: '/ignore\\s+(?:all\\s+)?previous\\s+(?:instructions|directions)/i'
    decision: block
"""


def _compile_rule_pattern(raw: str) -> re.Pattern[str]:
    """
    Accept either /pattern/flags or a bare pattern string.
    Supports i, m, s flags.
    """
    raw = (raw or "").strip()
    if not raw:
        return re.compile(r"(?!x)")  # never matches

    if len(raw) >= 2 and raw[0] == "/" and raw.rfind("/") > 0:
        last = raw.rfind("/")
        pat = raw[1:last]
        flag_str = raw[last + 1 :]
        flags = 0
        for ch in flag_str:
            if ch == "i":
                flags |= re.IGNORECASE
            elif ch == "m":
                flags |= re.MULTILINE
            elif ch == "s":
                flags |= re.DOTALL
        return re.compile(pat, flags)

    # Bare pattern
    return re.compile(raw)


@dataclass
class CompiledRule:
    id: str
    description: str
    decision: str  # "allow" | "block"
    regex: re.Pattern[str]


_policy_rules: List[CompiledRule] | None = None
_policy_version: str = "1"
_rules_path: Path | None = None
_last_mtime: float = 0.0


def _policy_path_from_settings() -> Path:
    s = get_settings()
    path_str = getattr(s, "POLICY_PATH", None) or str(
        Path(__file__).with_name("rules.yaml")
    )
    return Path(path_str)


def _load_rules(path: Path) -> Tuple[List[CompiledRule], str, float]:
    # Ensure file exists (CI might not have committed YAML yet)
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_DEFAULT_RULES_YAML, encoding="utf-8")

    txt = path.read_text(encoding="utf-8")
    data = yaml.safe_load(txt) or {}
    version = str(data.get("version", "1"))

    compiled: List[CompiledRule] = []
    for item in data.get("rules", []) or []:
        rid = str(item.get("id", "") or "").strip() or "unnamed"
        desc = str(item.get("description", "") or "")
        decision = str(item.get("decision", "block") or "block").lower()
        raw = str(item.get("regex") or item.get("pattern") or "")
        rx = _compile_rule_pattern(raw)
        compiled.append(
            CompiledRule(id=rid, description=desc, decision=decision, regex=rx)
        )

    mtime = path.stat().st_mtime
    return compiled, version, mtime


def _ensure_loaded() -> None:
    global _policy_rules, _policy_version, _rules_path, _last_mtime

    if _policy_rules is None:
        _rules_path = _policy_path_from_settings()
        _policy_rules, _policy_version, _last_mtime = _load_rules(_rules_path)
        return

    s = get_settings()
    auto = str(getattr(s, "POLICY_AUTO_RELOAD", "false")).lower() in (
        "1",
        "true",
        "yes",
    )
    if auto and _rules_path and _rules_path.exists():
        try:
            mtime = _rules_path.stat().st_mtime
        except OSError:
            mtime = 0.0
        if mtime > _last_mtime:
            _policy_rules, _policy_version, _last_mtime = _load_rules(_rules_path)


def reload_rules() -> dict[str, Any]:
    """Manual reload endpoint can call this."""
    global _policy_rules, _policy_version, _last_mtime, _rules_path
    _rules_path = _policy_path_from_settings()
    _policy_rules, _policy_version, _last_mtime = _load_rules(_rules_path)
    return {
        "policy_version": _policy_version,
        "rules_loaded": len(_policy_rules or []),
    }


# Back-compat for routes/admin.py which imports force_reload
def force_reload() -> dict[str, Any]:
    return reload_rules()


# -------------
# Redaction pass
# -------------
# Simple masks; these are intentionally broad, mirroring tests.
_REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"sk-[A-Za-z0-9]{16,}"), "[REDACTED:OPENAI_KEY]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED:AWS_ACCESS_KEY_ID]"),
    (
        re.compile(
            r"(?:-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----)"
        ),
        "[REDACTED:PRIVATE_KEY]",
    ),
]


def _maybe_redact(text: str) -> str:
    s = get_settings()
    enabled = str(getattr(s, "REDACT_SECRETS", "false")).lower() in (
        "1",
        "true",
        "yes",
    )
    if not enabled:
        return text
    out = text
    for pat, repl in _REDACTIONS:
        out = pat.sub(repl, out)
    return out


# ----------
# Evaluation
# ----------
def analyze(text: str) -> tuple[str, list[str], str]:
    """
    Returns (decision, rule_hits, reason).
    Decision is "block" if any rule triggers with decision=block; else "allow".
    """
    _ensure_loaded()
    rules = _policy_rules or []

    hits: list[str] = []
    for r in rules:
        try:
            if r.regex.search(text):
                hits.append(r.id)
        except re.error:
            # Skip malformed rules rather than crashing
            continue

    if hits:
        return "block", hits, f"High-risk rules matched: {', '.join(hits)}"
    return "allow", [], "No risk signals detected"


def evaluate_and_apply(text: str) -> dict[str, Any]:
    """
    Main entry point used by routes. Applies policy and redactions,
    emits audit.
    """
    _ensure_loaded()
    s = get_settings()

    # Optional size limit -> 413 is raised in the route layer; we only
    # return decision payloads here.
    # (Tests that exercise 413 go via the route layer; leaving this here
    # as a soft guard if needed.)
    max_chars = int(getattr(s, "PROMPT_MAX_CHARS", 0) or 0)
    if max_chars and len(text) > max_chars:
        # We *don't* raise here to keep behavior consistent; callers may
        # choose to 413 earlier. Still return a blocked decision so
        # callers who rely on this function directly are safe.
        decision, rule_hits, reason = (
            "block",
            ["payload:size_limit"],
            "Prompt exceeds maximum allowed size",
        )
    else:
        decision, rule_hits, reason = analyze(text)

    transformed = _maybe_redact(text)

    # Emit audit event; include request_id (empty if unknown) to satisfy mypy
    try:
        emit_decision_event(
            decision=decision,
            rule_hits=list(rule_hits),
            reason=reason,
            policy_version=str(_policy_version),
            prompt_text=text,
            request_id="",  # filled by caller/middleware in real app flows
        )
    except Exception:
        # Never let telemetry break the request
        pass

    return {
        "decision": decision,
        "rule_hits": list(rule_hits),
        "reason": reason,
        "policy_version": str(_policy_version),
        "transformed_text": transformed,
    }

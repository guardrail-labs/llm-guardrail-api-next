from __future__ import annotations

import os
import re
import threading
from copy import deepcopy
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Literal, Mapping, Optional, Pattern, Tuple

from app.config import get_settings
from app.models.verifier import VerifierInput
from app.services import runtime_flags, verifier_client as vcli
from app.services.config_store import get_policy_packs
from app.services.policy_packs import merge_packs

# Thread-safe counters and rule storage
_RULE_LOCK = threading.RLock()
_REDACTIONS_TOTAL = 0.0

# Live policy state sourced from policy packs
_RULES: Dict[str, Any] = {}
_RULES_VERSION: str = "unknown"
_PACK_REFS: List[Any] = []

# Track source file and mtime (for autoreload of legacy yaml)
_RULES_PATH: Optional[Path] = None
_RULES_MTIME: Optional[float] = None

# Compiled rule caches (legacy heuristics)
_COMPILED_RULES: Dict[str, List[Pattern[str]]] = {
    "secrets": [],
    "unsafe": [],
    "gray": [],
}

# Redaction patterns: (compiled_regex, replacement_label)
_REDACTIONS: List[Tuple[Pattern[str], str]] = []


class Action(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    CLARIFY = "clarify"


ClassifierOutcome = Literal["allow", "block", "ambiguous", "unknown"]
VerifierOutcome = Literal["allow", "block", "timeout", "error", "uncertain"]


def map_classifier_outcome_to_action(o: ClassifierOutcome) -> str:
    if o == "allow":
        return "allow"
    if o == "block":
        return "block_input_only"
    if o in ("ambiguous", "unknown"):
        return "clarify"
    return "clarify"


def map_verifier_outcome_to_action(o: VerifierOutcome) -> str:
    if o == "allow":
        return "allow"
    if o == "block":
        return "block_input_only"
    if o in ("timeout", "error", "uncertain"):
        return "clarify"
    return "clarify"


_INJECTION_FAMILIES = {"injection", "jailbreak"}


def _has_family(rule_hits: Mapping[str, Any], families: Iterable[str]) -> bool:
    fams = tuple(f + ":" for f in families)
    for key in (rule_hits or {}).keys():
        if key.startswith(fams):
            return True
    return False


def _coerce_action(val: str | None) -> Action | None:
    if not val:
        return None
    v = val.strip().lower()
    if v == Action.BLOCK.value:
        return Action.BLOCK
    if v == Action.CLARIFY.value:
        return Action.CLARIFY
    if v == Action.ALLOW.value:
        return Action.ALLOW
    return None


def get_active_policy() -> Dict[str, Any]:
    """Return a deep copy of the active policy for safe read-only use."""

    return deepcopy(_RULES)


def get_pack_refs() -> List[dict]:
    """Return [{name, path}] for the last merged pack refs."""

    return [{"name": r.name, "path": r.path} for r in _PACK_REFS]


def resolve_injection_default_action() -> Action:
    val = runtime_flags.get("policy_default_injection_action")
    coerced = _coerce_action(str(val))
    return coerced or Action.BLOCK


def apply_injection_default(decision: Dict[str, Any]) -> Dict[str, Any]:
    action = decision.get("action")
    hits = decision.get("rule_hits") or {}

    if action and action != Action.ALLOW.value:
        return decision

    if _has_family(hits, _INJECTION_FAMILIES):
        decision["action"] = resolve_injection_default_action().value
    return decision


def maybe_route_to_verifier(decision: Dict[str, Any], *, text: str) -> Dict[str, Any]:
    """Route to verifier if gray-area conditions are met and track outcome."""
    s = get_settings()
    if not getattr(s, "verifier_enabled", False):
        return decision

    action = (decision.get("action") or "allow").lower()
    if action == "clarify":
        # Already clarified upstream; don't re-run
        return decision

    hits = decision.get("rule_hits") or {}
    inp = VerifierInput(text=text, rule_hits=hits, context=None)
    try:
        res = vcli.call_verifier(inp)
        v_dec = str(res.decision).lower()
        # Attach minimal adjudication snippet to debug
        if decision.get("debug") is not None:
            dbg = decision["debug"]
            dbg.setdefault("verifier", {})
            dbg["verifier"].update(
                {
                    "provider": getattr(res, "provider", "unknown"),
                    "decision": v_dec,
                    "latency_ms": getattr(res, "latency_ms", None),
                }
            )
        # Apply decision if recognized, else fallback
        if v_dec in {"block", "clarify", "allow"}:
            decision["action"] = v_dec
            try:
                # Increment metrics (labels: verifier, outcome)
                from app.telemetry import metrics as tmetrics  # local import to avoid cycles

                tmetrics.inc_verifier_outcome(getattr(res, "provider", "unknown"), v_dec)
            except Exception:
                pass
        else:
            decision["action"] = s.verifier_default_action
            try:
                from app.telemetry import metrics as tmetrics

                tmetrics.inc_verifier_outcome(getattr(res, "provider", "unknown"), "fallback")
            except Exception:
                pass
    except Exception:
        # Transport or provider error → fallback action
        decision["action"] = s.verifier_default_action
        try:
            from app.telemetry import metrics as tmetrics

            tmetrics.inc_verifier_outcome(getattr(s, "verifier_provider", "unknown"), "error")
        except Exception:
            pass
    return decision


def _env(name: str) -> Optional[str]:
    v = os.environ.get(name)
    return v if v and v.strip() else None


def _load_yaml(path: Path) -> Dict[str, Any]:
    """
    Load a minimal rules yaml.

    Example:
        version: "9"
        deny:
          - id: block_phrase
            pattern: "(?i)do not allow this"
            flags: ["i"]

    Uses PyYAML if available; otherwise falls back to a tiny parser that handles the
    test-fixture shape (version + deny items with pattern and optional flags).
    """
    # Try PyYAML first
    try:
        import yaml  # noqa: F401

        with path.open("r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        if isinstance(raw, dict):
            return raw
    except Exception:
        # Fall through to naive parser
        pass

    # Naive fallback: extract version and deny entries from plain text
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        return {}

    data: Dict[str, Any] = {}

    # version:
    m = re.search(r"(?m)^\s*version\s*:\s*['\"]?([^'\"]+)['\"]?\s*$", text)
    if m:
        data["version"] = m.group(1).strip()

    # deny: look for blocks that contain "pattern:" (very simple split/scan)
    deny: List[Dict[str, Any]] = []
    for block in re.split(r"(?m)^\s*-\s*", text):
        if "pattern:" not in block:
            continue
        pat_m = re.search(r"pattern\s*:\s*['\"](.+?)['\"]", block)
        fl_m = re.search(r"flags\s*:\s*\[(.*?)\]", block)
        item: Dict[str, Any] = {}
        if pat_m:
            item["pattern"] = pat_m.group(1)
        if fl_m:
            flags = [p.strip().strip("'\"") for p in fl_m.group(1).split(",") if p.strip()]
            item["flags"] = flags
        if item:
            deny.append(item)

    if deny:
        data["deny"] = deny

    return data


def _load_policy_from_packs() -> Tuple[Dict[str, Any], str]:
    """Load and merge policy packs producing merged rules and version."""

    names = get_policy_packs()
    merged, version, refs = merge_packs(names)

    if not isinstance(merged, dict):
        merged = {}

    settings = merged.get("settings")
    if not isinstance(settings, dict):
        merged["settings"] = {}

    rules = merged.get("rules")
    if not isinstance(rules, dict):
        rules = {}
        merged["rules"] = rules

    rules.setdefault("deny", [])
    rules.setdefault("allow", [])
    rules.setdefault("redact", [])
    rules.setdefault("verifiers", [])

    global _PACK_REFS
    _PACK_REFS = list(refs)

    return merged, version


def _compile_rules_from_dict(
    cfg: Optional[Dict[str, Any]], *, version: Optional[str] = None
) -> None:
    """Compile rules using an optional yaml dict. Merge with built-ins."""
    global _COMPILED_RULES, _REDACTIONS, _RULES_VERSION
    with _RULE_LOCK:
        # --- Secrets (sample subset) ---
        secrets: List[Pattern[str]] = [
            re.compile(r"sk-[A-Za-z0-9]{16,}"),  # OpenAI-style key
            re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key id
        ]
        pk_marker = r"(?:-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----)"
        secrets.append(re.compile(pk_marker))

        # --- Unsafe (deny rules) ---
        unsafe: List[Pattern[str]] = [
            # sensible defaults in absence of yaml
            re.compile(r"\b(hack|exploit).*(wifi|router|wpa2)", re.I),
            re.compile(r"\b(make|build).*(bomb|weapon|explosive)", re.I),
        ]

        # If yaml provided, replace/extend unsafe with deny list
        if cfg and isinstance(cfg.get("deny"), list):
            unsafe = []
            for item in cfg["deny"]:
                if not isinstance(item, dict):
                    continue
                pat = item.get("pattern")
                if not isinstance(pat, str) or not pat:
                    continue
                flags = 0
                for fl in item.get("flags") or []:
                    if isinstance(fl, str) and fl.lower() == "i":
                        flags |= re.IGNORECASE
                unsafe.append(re.compile(pat, flags))

        # --- Gray area (likely jailbreaks / intent unclear) ---
        gray: List[Pattern[str]] = [
            re.compile(r"\bignore\s+previous\s+instructions\b", re.I),
            re.compile(r"\bpretend\s+to\s+be\s+DAN\b", re.I),
            re.compile(r"\bthis\s+is\s+for\s+education\s+only\b", re.I),
        ]

        _COMPILED_RULES = {"secrets": secrets, "unsafe": unsafe, "gray": gray}

        # Redactions: map to labels for auditability
        _REDACTIONS = [
            (re.compile(r"sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ"), "[REDACTED:OPENAI_KEY]"),
            (re.compile(r"sk-[A-Za-z0-9]{16,}"), "[REDACTED:OPENAI_KEY]"),
            (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED:AWS_ACCESS_KEY_ID]"),
            (re.compile(pk_marker), "[REDACTED:PRIVATE_KEY]"),
        ]

        # Set version (yaml wins; else bump)
        if version is not None:
            _RULES_VERSION = str(version)
        elif cfg and isinstance(cfg.get("version"), (str, int)):
            _RULES_VERSION = str(cfg["version"])
        else:
            try:
                current = int(_RULES_VERSION)
            except (TypeError, ValueError):
                current = 0
            _RULES_VERSION = str(current + 1)


def _maybe_autoreload() -> None:
    """
    If POLICY_AUTORELOAD=true, reload when the file mtime changes.
    Also recompile when rules are not yet loaded.
    """
    auto = (_env("POLICY_AUTORELOAD") or "false").lower() == "true"
    if not auto:
        return

    path_str = _env("POLICY_RULES_PATH")
    if not path_str:
        return

    path = Path(path_str)
    if not path.exists():
        return

    global _RULES_MTIME, _RULES_PATH
    mtime = path.stat().st_mtime
    if _RULES_MTIME is None or mtime != _RULES_MTIME or _RULES_PATH != path:
        cfg = _load_yaml(path)
        _compile_rules_from_dict(cfg, version=_RULES_VERSION)
        _RULES_MTIME = mtime
        _RULES_PATH = path


def _compile_rules_initial() -> None:
    """Initial compile; consider static yaml if provided (without autoreload)."""
    path_str = _env("POLICY_RULES_PATH")
    cfg = None
    if path_str and Path(path_str).exists():
        try:
            cfg = _load_yaml(Path(path_str))
        except Exception:
            cfg = None
    _compile_rules_from_dict(cfg, version=_RULES_VERSION)


# Initial load on import
_compile_rules_initial()


def force_reload() -> str:
    """Reload active policy from configured packs."""

    global _RULES, _RULES_VERSION

    merged, version = _load_policy_from_packs()
    _RULES = merged
    _RULES_VERSION = str(version)

    rules_block: Optional[Dict[str, Any]]
    rules_val = merged.get("rules")
    if isinstance(rules_val, Mapping):
        rules_block = dict(rules_val)
    else:
        rules_block = None

    _compile_rules_from_dict(rules_block, version=_RULES_VERSION)
    return _RULES_VERSION


def current_rules_version() -> str:
    """Return current rules version as string (tests expect string)."""
    _maybe_autoreload()
    return _RULES_VERSION


def reload_rules() -> Dict[str, Any]:
    """Reload policy packs and optional legacy YAML overrides."""

    global _RULES_MTIME, _RULES_PATH

    try:
        version = force_reload()
    except Exception:
        version = _RULES_VERSION

    path_str = _env("POLICY_RULES_PATH")
    loaded_path: Optional[Path] = None
    cfg = None
    if path_str:
        candidate = Path(path_str)
        if candidate.exists():
            try:
                cfg = _load_yaml(candidate)
                loaded_path = candidate
            except Exception:
                cfg = None
        else:
            cfg = None

    if cfg is not None:
        _compile_rules_from_dict(cfg, version=version)
        if loaded_path is not None:
            _RULES_MTIME = loaded_path.stat().st_mtime
            _RULES_PATH = loaded_path
    else:
        _RULES_MTIME = None
        _RULES_PATH = None

    return {
        "policy_version": current_rules_version(),
        "version": current_rules_version(),  # alias for older callers
        "rules_count": sum(len(v) for v in _COMPILED_RULES.values()),
        "redaction_patterns": len(_REDACTIONS),
        "rules_loaded": True,
    }


def get_redactions_total() -> float:
    return float(_REDACTIONS_TOTAL)


def _apply_redactions(text: str) -> Tuple[str, int]:
    """Apply redaction patterns to text; return (sanitized_text, count)."""
    global _REDACTIONS_TOTAL
    count = 0
    out = text
    for rx, label in _REDACTIONS:
        new = re.sub(rx, label, out)
        if new != out:
            count += 1
            out = new
    if count:
        with _RULE_LOCK:
            _REDACTIONS_TOTAL += float(count)
    return out, count


def rule_hits(text: str) -> List[Dict[str, Any]]:
    """Return a list of rule hits with lightweight tagging."""
    _maybe_autoreload()
    hits: List[Dict[str, Any]] = []
    for tag, patterns in _COMPILED_RULES.items():
        for rx in patterns:
            if rx.search(text):
                hits.append({"tag": tag, "pattern": rx.pattern})
    return hits


def score_and_decide(text: str, hits: List[Dict[str, Any]]) -> Tuple[str, int]:
    """
    Simple scoring heuristic:

      - unsafe hit: +100 (deny)
      - secret hit: +50 (sanitize)
      - gray hit: +40 (clarify)

    Decision order:
      1) unsafe -> deny
      2) secrets only -> sanitize
      3) gray -> clarify
      4) else -> allow

    Returns (action, risk_score)
    """
    score = 0
    tags = {h.get("tag") for h in hits}

    if "unsafe" in tags:
        score += 100
        return "deny", score

    if "secrets" in tags:
        score += 50
        return "sanitize", score

    if "gray" in tags:
        score += 40
        return "clarify", score

    return "allow", score


def apply_policies(text: str) -> Dict[str, Any]:
    """
    Full ingress policy pass for base:

      - detect rule hits
      - score & choose action
      - apply redactions (if any)
    """
    hits = rule_hits(text)
    action, risk = score_and_decide(text, hits)
    sanitized, redactions = _apply_redactions(text)
    return {
        "action": action,
        "risk_score": risk,
        "sanitized_text": sanitized,
        "redactions": redactions,
        "hits": hits,
    }


def evaluate_and_apply(text: str) -> Dict[str, Any]:
    """
    Legacy helper preserved for routes that import:
      from app.services.policy import evaluate_and_apply

    Returns a shape compatible with older code paths:

      - action
      - risk_score
      - transformed_text (sanitized_text)
      - rule_hits (list of dicts; routes may flatten to strings)
      - redactions
      - decisions (empty list; routes can append details)
    """
    res = apply_policies(text)
    return {
        "action": res["action"],
        "risk_score": int(res.get("risk_score", 0)),
        "transformed_text": res.get("sanitized_text", text),
        "rule_hits": list(res.get("hits", [])),
        "redactions": int(res.get("redactions", 0)),
        "decisions": [],
    }


# ---------------------------------------------------------------------------
# Sanitization helpers
# ---------------------------------------------------------------------------

# --- Normalized rule family tags (must match tests/docs) ---
# secrets:*, pi:*, payload:*, policy:deny:*
# We'll normalize specific hits into these families.

# Secrets (common)
_OPENAI_KEY = re.compile(r"\bsk-[A-Za-z0-9]{16,}\b")
_AWS_ACCESS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GITHUB_PAT = re.compile(r"\bghp_[A-Za-z0-9]{36}\b")
_SLACK_TOKEN = re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,48}\b")
_GOOGLE_API_KEY = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")
_STRIPE_SECRET = re.compile(r"\bsk_(?:live|test)_[0-9a-zA-Z]{24}\b")
_STRIPE_PUB = re.compile(r"\bpk_(?:live|test)_[0-9a-zA-Z]{24}\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")
_BEARER = re.compile(r"\bBearer\s+[A-Za-z0-9_\-\.]{20,}\b")
_PRIV_KEY_BOUNDS = re.compile(r"(?:-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----)")

# PII (lightweight patterns; we do not claim legal-grade recall)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE = re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

# Payload / prompt-injection hints (keep conservative to avoid false positives)
_PROMPT_INJ = re.compile(
    r"(?i)\b(ignore (all|any) previous (rules|instructions)|"
    r"system prompt|do not follow policy|override policy)\b"
)

# We redact these with neutral placeholders. Keep short to preserve readability.
REDACTION_MAP: Dict[str, str] = {
    "secrets:openai_key": "[REDACTED:OPENAI_KEY]",
    "secrets:aws_key": "[REDACTED:AWS_ACCESS_KEY_ID]",
    "secrets:github_pat": "[REDACTED:GITHUB_PAT]",
    "secrets:slack_token": "[REDACTED:SLACK_TOKEN]",
    "secrets:google_api_key": "[REDACTED:GOOGLE_API_KEY]",
    "secrets:stripe_secret": "[REDACTED:STRIPE_SECRET]",
    "secrets:stripe_pub": "[REDACTED:STRIPE_PUBLISHABLE]",
    "secrets:jwt": "[REDACTED:JWT]",
    "secrets:bearer": "[REDACTED:BEARER]",
    "secrets:private_key_marker": "[REDACTED:PRIVATE_KEY]",
    "pi:email": "[REDACTED:EMAIL]",
    "pi:phone": "[REDACTED:PHONE]",
    "pi:ssn": "[REDACTED:SSN]",
    "payload:prompt_injection": "[REDACTED:INJECTION]",
}

# Order matters to produce stable redaction behavior
REDACTION_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    (_OPENAI_KEY, "secrets:openai_key", REDACTION_MAP["secrets:openai_key"]),
    (_AWS_ACCESS_KEY, "secrets:aws_key", REDACTION_MAP["secrets:aws_key"]),
    (_GITHUB_PAT, "secrets:github_pat", REDACTION_MAP["secrets:github_pat"]),
    (
        _SLACK_TOKEN,
        "secrets:slack_token",
        REDACTION_MAP["secrets:slack_token"],
    ),
    (
        _GOOGLE_API_KEY,
        "secrets:google_api_key",
        REDACTION_MAP["secrets:google_api_key"],
    ),
    (
        _STRIPE_SECRET,
        "secrets:stripe_secret",
        REDACTION_MAP["secrets:stripe_secret"],
    ),
    (
        _STRIPE_PUB,
        "secrets:stripe_pub",
        REDACTION_MAP["secrets:stripe_pub"],
    ),
    (_JWT, "secrets:jwt", REDACTION_MAP["secrets:jwt"]),
    (_BEARER, "secrets:bearer", REDACTION_MAP["secrets:bearer"]),
    (
        _PRIV_KEY_BOUNDS,
        "secrets:private_key_marker",
        REDACTION_MAP["secrets:private_key_marker"],
    ),
    (_EMAIL, "pi:email", REDACTION_MAP["pi:email"]),
    (_PHONE, "pi:phone", REDACTION_MAP["pi:phone"]),
    (_SSN, "pi:ssn", REDACTION_MAP["pi:ssn"]),
    (
        _PROMPT_INJ,
        "payload:prompt_injection",
        REDACTION_MAP["payload:prompt_injection"],
    ),
]


def get_stream_redaction_patterns() -> List[Tuple[re.Pattern[str], str, str]]:
    """
    Return (regex, tag, replacement) tuples mirroring REDACTION_PATTERNS,
    ordered for stable behavior in streaming mode.
    """

    return list(REDACTION_PATTERNS)


def _normalize_family(hit: str) -> str:
    """
    Map specific hits to their normalized families:
    secrets:* | pi:* | payload:* | policy:deny:*
    """
    if hit.startswith("secrets:"):
        return "secrets:*"
    if hit.startswith("pi:"):
        return "pi:*"
    if hit.startswith("payload:"):
        return "payload:*"
    if hit.startswith("policy:deny:"):
        return "policy:deny:*"
    # default: pass through
    return hit


def sanitize_text(
    text: str, debug: bool = False
) -> Tuple[str, List[str], int, List[Dict[str, Any]]]:
    """
    Apply conservative redactions and return:
      - sanitized_text
      - normalized rule_hits (families)
      - redaction_count
      - debug_matches (optional)
    """
    hits: List[str] = []
    debug_matches: List[Dict[str, Any]] = []
    redactions = 0
    out = text

    # Walk each pattern; replace iteratively to gather counts and hits
    for pattern, tag, replacement in REDACTION_PATTERNS:
        # Find all occurrences before substitution (for debug/counting)
        occurrences = list(pattern.finditer(out))
        if not occurrences:
            continue

        # Perform substitution
        out, n_subs = pattern.subn(replacement, out)
        redactions += n_subs
        hits.append(tag)

        if debug:
            for m in occurrences[:5]:  # cap to avoid huge debug payloads
                span = {"start": m.start(), "end": m.end()}
                sample = text[m.start() : m.end()]
                debug_matches.append({"tag": tag, "span": span, "sample": sample})

    # Deduplicate hits and normalize families
    families = sorted({_normalize_family(h) for h in hits})

    return out, families, redactions, (debug_matches if debug else [])


# Note:
# - Keep existing public functions like get_redactions_total(), reload_rules(), etc.
# - Call sanitize_text() from the evaluate route to apply ingress redactions.


def map_verifier_outcome_to_headers(outcome: Dict[str, Any]) -> tuple[str, str]:
    """Map a verifier outcome dict to (decision, mode) headers."""

    status = str(outcome.get("status", "")).lower()
    if status == "unsafe":
        return "deny", "live"
    if status == "safe":
        return "allow", "live"
    if status in {"error", "timeout", "ambiguous"}:
        return "clarify", "live"
    return "clarify", "live"


# Initialize live policy on import, but avoid crashing if packs misconfigure.
try:
    if _RULES_VERSION == "unknown":
        force_reload()
except Exception:
    # Defer failures to first explicit use; version remains "unknown".
    pass

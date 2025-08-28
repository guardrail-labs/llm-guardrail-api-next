from __future__ import annotations

import os
import re
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern, Tuple

# -------------------------
# Global state & versioning
# -------------------------

_RULE_LOCK = threading.RLock()
_REDACTIONS_TOTAL = 0.0

# Monotonic rules version; tests want string in responses
_RULES_VERSION = 1

# Compiled rule caches (filled by _compile_rules)
_RULES: Dict[str, List[Pattern[str]]] = {
    "secrets": [],
    "unsafe": [],
    "gray": [],
}
# Redaction patterns: (compiled_regex, replacement_label)
_REDACTIONS: List[Tuple[Pattern[str], str]] = []

# External rules (optional)
_RULES_PATH: Optional[Path] = None
_RULES_MTIME: Optional[float] = None
_RULES_LOADED: bool = False


# ------------------------------------
# Minimal YAML-like rules file support
# ------------------------------------

def _parse_minimal_yaml(text: str) -> Dict[str, Any]:
    """
    Super-minimal parser for a tiny subset used in tests.
    Supports:
      version: <int>
      deny:
        - id: <str>
          pattern: "<regex>"
          flags: ["i", "m"]   (optional)
    """
    data: Dict[str, Any] = {"version": None, "deny": []}
    lines = [ln.rstrip() for ln in text.splitlines()]
    i = 0
    while i < len(lines):
        ln = lines[i].strip()
        if ln.startswith("version:"):
            try:
                data["version"] = int(ln.split(":", 1)[1].strip())
            except Exception:
                data["version"] = None
            i += 1
            continue
        if ln.startswith("deny:"):
            i += 1
            current: Dict[str, Any] = {}
            while i < len(lines):
                raw = lines[i]
                s = raw.strip()
                if not s:
                    i += 1
                    continue
                if not raw.startswith("  "):
                    break  # end of this section
                if s.startswith("- "):
                    if current:
                        data["deny"].append(current)
                    current = {}
                    s = s[2:].strip()
                    if s and ":" in s:
                        k, v = s.split(":", 1)
                        current[k.strip()] = v.strip().strip('"')
                    i += 1
                    continue
                if ":" in s:
                    k, v = s.split(":", 1)
                    k = k.strip()
                    v = v.strip()
                    if k == "flags":
                        v = v.strip("[]").strip()
                        flags = [p.strip().strip('"').strip("'") for p in v.split(",") if p]
                        current["flags"] = flags
                    else:
                        current[k] = v.strip().strip('"')
                i += 1
            if current:
                data["deny"].append(current)
            continue
        i += 1
    return data


def _load_external_rules_if_configured() -> None:
    """
    If POLICY_RULES_PATH points to a file, (re)load deny rules and bump version.
    """
    global _RULES_PATH, _RULES_MTIME, _RULES_LOADED, _RULES_VERSION, _RULES
    path = os.environ.get("POLICY_RULES_PATH")
    if not path:
        _RULES_LOADED = False
        return
    p = Path(path)
    if not p.is_file():
        _RULES_LOADED = False
        return
    try:
        mtime = p.stat().st_mtime
    except Exception:
        _RULES_LOADED = False
        return

    if _RULES_PATH != p or _RULES_MTIME != mtime:
        text = p.read_text(encoding="utf-8", errors="ignore")
        parsed = _parse_minimal_yaml(text)
        deny_rules: List[Pattern[str]] = []
        for item in parsed.get("deny", []):
            pat = str(item.get("pattern") or "")
            flags_list = item.get("flags") or []
            fl = 0
            if isinstance(flags_list, list):
                for f in flags_list:
                    fl |= re.IGNORECASE if str(f).lower() == "i" else 0
                    fl |= re.MULTILINE if str(f).lower() == "m" else 0
            try:
                deny_rules.append(re.compile(pat, fl))
            except re.error:
                continue  # ignore invalid regex in tests

        with _RULE_LOCK:
            # Replace/extend UNSAFE with file-provided deny rules
            _RULES["unsafe"] = _RULES.get("unsafe", [])[:0] + deny_rules
            ver = parsed.get("version")
            if isinstance(ver, int) and ver > 0:
                _RULES_VERSION = ver
            else:
                _RULES_VERSION += 1
            _RULES_PATH = p
            _RULES_MTIME = mtime
            _RULES_LOADED = True


def _maybe_autoreload() -> None:
    if (os.environ.get("POLICY_AUTORELOAD") or "false").lower() == "true":
        _load_external_rules_if_configured()


# -------------------------
# Base rules & redactions
# -------------------------

def _compile_rules() -> None:
    """
    Compile in-memory base rules. External rules may overlay/replace UNSAFE.
    """
    global _RULES, _REDACTIONS, _RULES_VERSION
    with _RULE_LOCK:
        # --- Secrets (sample subset) ---
        secrets: List[Pattern[str]] = [
            re.compile(r"sk-[A-Za-z0-9]{16,}"),   # OpenAI-style key
            re.compile(r"AKIA[0-9A-Z]{16}"),      # AWS access key id
        ]
        pk_marker = r"(?:-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----)"
        secrets.append(re.compile(pk_marker))

        # --- Unsafe (clear policy violations / wrongdoing intent) ---
        unsafe: List[Pattern[str]] = [
            re.compile(r"\b(hack|exploit).*(wifi|router|wpa2)", re.I),
            re.compile(r"\b(make|build).*(bomb|weapon|explosive)", re.I),
            # Heuristic for long base64-like blobs
            re.compile(r"[A-Za-z0-9+/=]{128,}"),
        ]

        # --- Gray area (likely jailbreaks / intent unclear) ---
        gray: List[Pattern[str]] = [
            re.compile(r"\bignore\s+previous\s+instructions\b", re.I),
            re.compile(r"\bpretend\s+to\s+be\s+DAN\b", re.I),
            re.compile(r"\bthis\s+is\s+for\s+education\s+only\b", re.I),
        ]

        _RULES = {"secrets": secrets, "unsafe": unsafe, "gray": gray}

        # Redactions: map to labels for auditability
        _REDACTIONS = [
            (re.compile(r"sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ"), "[REDACTED:OPENAI_KEY]"),
            (re.compile(r"sk-[A-Za-z0-9]{16,}"), "[REDACTED:OPENAI_KEY]"),
            (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED:AWS_ACCESS_KEY_ID]"),
            (re.compile(pk_marker), "[REDACTED:PRIVATE_KEY]"),
        ]

        _RULES_VERSION += 1

    # Overlay from file if configured
    _load_external_rules_if_configured()


# Initial compile on import
_compile_rules()


def current_rules_version() -> str:
    """Return the current rules version as a string (tests expect str)."""
    return str(_RULES_VERSION)


def reload_rules() -> Dict[str, Any]:
    """
    Recompile/refresh rules and return metadata as a dict that callers
    can `.get(...)` and `**`-unpack without overriding string version.
    """
    _compile_rules()
    return {
        "reloaded": True,
        "policy_version": _RULES_VERSION,          # numeric copy (optional)
        "version": str(_RULES_VERSION),            # string for contracts
        "rules_count": sum(len(v) for v in _RULES.values()),
        "redaction_patterns": len(_REDACTIONS),
        "rules_loaded": bool(_RULES_LOADED),
    }


# Some code may import this older alias.
force_reload = reload_rules


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
            count += 1  # naive increment; sufficient for base
            out = new
    if count:
        with _RULE_LOCK:
            _REDACTIONS_TOTAL += float(count)
    return out, count


def rule_hits(text: str) -> List[Dict[str, Any]]:
    """Return a list of rule hits with lightweight tagging (with autoreload)."""
    _maybe_autoreload()
    hits: List[Dict[str, Any]] = []
    for tag, patterns in _RULES.items():
        for rx in patterns:
            if rx.search(text):
                hits.append({"tag": tag, "pattern": rx.pattern})
    return hits


def score_and_decide(text: str, hits: List[Dict[str, Any]]) -> Tuple[str, int]:
    """
    Simple scoring heuristic:
      - unsafe hit: +100 (deny)
      - secret hit: +50 (sanitize)
      - gray hit: +40 (clarify if no unsafe)
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


# --- Back-compat alias for legacy callers (e.g., app/routes/output.py) ---

def evaluate_and_apply(text: str) -> Dict[str, Any]:
    """
    Legacy helper preserved for routes that import:
        from app.services.policy import evaluate_and_apply
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

from __future__ import annotations

import os
import re
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern, Tuple

# Thread-safe counters and rule storage
_RULE_LOCK = threading.RLock()
_REDACTIONS_TOTAL = 0.0

# Versioning for rules (string to satisfy response contracts/tests)
_RULES_VERSION: str = "1"

# Track source file and mtime (for autoreload)
_RULES_PATH: Optional[Path] = None
_RULES_MTIME: Optional[float] = None

# Compiled rule caches
_RULES: Dict[str, List[Pattern[str]]] = {
    "secrets": [],
    "unsafe": [],
    "gray": [],
}

# Redaction patterns: (compiled_regex, replacement_label)
_REDACTIONS: List[Tuple[Pattern[str], str]] = []


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
            flags = [
                p.strip().strip("'\"")
                for p in fl_m.group(1).split(",")
                if p.strip()
            ]
            item["flags"] = flags
        if item:
            deny.append(item)

    if deny:
        data["deny"] = deny

    return data


def _compile_rules_from_dict(cfg: Optional[Dict[str, Any]]) -> None:
    """Compile rules using an optional yaml dict. Merge with built-ins."""
    global _RULES, _REDACTIONS, _RULES_VERSION
    with _RULE_LOCK:
        # --- Secrets (sample subset) ---
        secrets: List[Pattern[str]] = [
            re.compile(r"sk-[A-Za-z0-9]{16,}"),  # OpenAI-style key
            re.compile(r"AKIA[0-9A-Z]{16}"),     # AWS access key id
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
                for fl in (item.get("flags") or []):
                    if isinstance(fl, str) and fl.lower() == "i":
                        flags |= re.IGNORECASE
                unsafe.append(re.compile(pat, flags))

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

        # Set version (yaml wins; else bump)
        if cfg and isinstance(cfg.get("version"), (str, int)):
            _RULES_VERSION = str(cfg["version"])
        else:
            _RULES_VERSION = str(int(_RULES_VERSION) + 1)


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
        _compile_rules_from_dict(cfg)
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
    _compile_rules_from_dict(cfg)


# Initial load on import
_compile_rules_initial()


def current_rules_version() -> str:
    """Return current rules version as string (tests expect string)."""
    _maybe_autoreload()
    return _RULES_VERSION


def reload_rules() -> Dict[str, Any]:
    """
    Recompile rules and return metadata.
    If POLICY_RULES_PATH is set, (re)load from that path.
    """
    path_str = _env("POLICY_RULES_PATH")
    cfg = None
    if path_str and Path(path_str).exists():
        try:
            cfg = _load_yaml(Path(path_str))
        except Exception:
            cfg = None
    _compile_rules_from_dict(cfg)

    global _RULES_MTIME, _RULES_PATH
    if path_str and Path(path_str).exists():
        p = Path(path_str)
        _RULES_MTIME = p.stat().st_mtime
        _RULES_PATH = p
    else:
        _RULES_MTIME = None
        _RULES_PATH = None

    return {
        "policy_version": current_rules_version(),
        "version": current_rules_version(),  # alias for older callers
        "rules_count": sum(len(v) for v in _RULES.values()),
        "redaction_patterns": len(_REDACTIONS),
        "rules_loaded": True,
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

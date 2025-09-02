from __future__ import annotations

import re
from threading import RLock
from typing import Any, Dict, List, Pattern, Tuple

# Global compiled rules: list of (regex, replacement)
_PATTERNS: List[Tuple[Pattern[str], str]] = []
_LOCK = RLock()


def _fetch_json(url: str) -> Dict[str, Any]:
    """
    Placeholder impl. Tests monkeypatch this function to return a spec:
      {
        "version": "...",
        "redactions": [
          {"pattern": r"...", "tag": "...", "replacement": "..."},
          ...
        ],
      }
    In production you could fetch via requests/httpx.
    """
    # Keep default no-op; tests replace this with a stub.
    return {"version": "empty", "redactions": []}


def reload_from_urls(urls: List[str]) -> int:
    """
    Load threat-feed rules from the given URLs (comma-separated in env in tests),
    compile regex patterns, and atomically replace the active rule set.

    Returns the total number of compiled redaction rules.
    """
    compiled: List[Tuple[Pattern[str], str]] = []
    total = 0
    for u in urls:
        try:
            spec = _fetch_json(u)  # tests monkeypatch this
        except Exception:
            continue
        redactions = (spec or {}).get("redactions", []) or []
        for entry in redactions:
            pat = entry.get("pattern")
            repl = entry.get("replacement") or "[REDACTED]"
            if not isinstance(pat, str) or not pat:
                continue
            try:
                rx = re.compile(pat)
                compiled.append((rx, repl))
                total += 1
            except re.error:
                # Skip bad patterns
                continue

    with _LOCK:
        _PATTERNS.clear()
        _PATTERNS.extend(compiled)

    return total


def apply_dynamic_redactions(text: str) -> str:
    """
    Apply the currently active threat-feed redactions to the input text.
    """
    if not text:
        return text
    with _LOCK:
        patterns = list(_PATTERNS)
    for rx, repl in patterns:
        text = rx.sub(repl, text)
    return text

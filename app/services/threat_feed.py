# app/services/threat_feed.py
from __future__ import annotations

import os
import re
from threading import RLock
from typing import Any, Dict, List, Pattern, Tuple

# Compiled rule: (regex, replacement, tag)
_Rules: List[Tuple[Pattern[str], str, str]] = []
_LOCK = RLock()


def _truthy(val: object) -> bool:
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


def threat_feed_enabled() -> bool:
    """
    Gate for dynamic redactions feature.
    Tests toggle via env THREAT_FEED_ENABLED.
    """
    return _truthy(os.environ.get("THREAT_FEED_ENABLED", "false"))


def _fetch_json(url: str) -> Dict[str, Any]:
    """
    Placeholder implementation. Tests monkeypatch this to return:
    {
      "version": "test",
      "redactions": [
        {
          "pattern": r"...",
          "tag": "secrets:vendor_token",
          "replacement": "[REDACTED:VENDOR_TOKEN]",
        },
        ...
      ],
    }
    """
    # Default no-op payload.
    return {"version": "empty", "redactions": []}


def reload_from_urls(urls: List[str]) -> int:
    """
    Fetch and compile redaction rules from the given URLs
    (using _fetch_json, which tests monkeypatch).

    Returns the number of compiled rules.
    """
    compiled: List[Tuple[Pattern[str], str, str]] = []
    total = 0

    for u in urls:
        try:
            spec = _fetch_json(u)
        except Exception:
            continue

        redactions = (spec or {}).get("redactions", []) or []
        for entry in redactions:
            pat = entry.get("pattern")
            tag = entry.get("tag") or "threat_feed"
            repl = entry.get("replacement") or "[REDACTED]"
            if not isinstance(pat, str) or not pat:
                continue
            try:
                rx = re.compile(pat)
            except re.error:
                # Skip invalid regex
                continue
            compiled.append((rx, repl, tag))
            total += 1

    with _LOCK:
        _Rules.clear()
        _Rules.extend(compiled)

    return total


def refresh_from_env() -> int:
    """
    Convenience helper used by some routes:
    reads THREAT_FEED_URLS (comma-separated), reloads, returns compiled count.
    """
    urls_env = os.environ.get("THREAT_FEED_URLS", "") or ""
    urls: List[str] = [u.strip() for u in urls_env.split(",") if u.strip()]
    if not urls:
        # Clearing rules when no URLs is safer (keeps behavior deterministic)
        with _LOCK:
            _Rules.clear()
        return 0
    return reload_from_urls(urls)


def apply_dynamic_redactions(
    text: str,
    debug: bool = False,
) -> Tuple[str, Dict[str, int], int, List[str]]:
    """
    Apply active threat-feed redactions.

    Returns:
      - sanitized text (str)
      - families map (dict[tag -> count]) for aggregation
      - total redactions applied (int)
      - debug matches (list[str]) when debug=True else []

    Notes:
      * Multiple rules may match; replacements are applied sequentially.
      * We count matches via regex finditer BEFORE substitution so counts reflect
        how many occurrences were present.
      * Also increments a wildcard family "<prefix>:*" derived from tag prefix
        before the first ":" (e.g., "secrets:*").
    """
    if not text:
        return text, {}, 0, []

    with _LOCK:
        rules_snapshot = list(_Rules)

    families: Dict[str, int] = {}
    debug_matches: List[str] = []
    total = 0
    out = text

    for rx, repl, tag in rules_snapshot:
        # Count occurrences first
        matches = list(rx.finditer(out))
        n = len(matches)
        if n == 0:
            continue

        total += n
        # Specific tag count
        families[tag] = families.get(tag, 0) + n
        # Wildcard family (e.g., "secrets:*")
        if ":" in tag:
            prefix = tag.split(":", 1)[0]
            wildcard = f"{prefix}:*"
            families[wildcard] = families.get(wildcard, 0) + n

        if debug:
            # Record a compact representation of matches (tag + first 50 chars)
            for m in matches:
                span_txt = m.group(0)
                debug_matches.append(f"{tag}:{span_txt[:50]}")

        # Apply substitution
        out = rx.sub(repl, out)

    return out, families, total, (debug_matches if debug else [])

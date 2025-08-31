from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple, cast
from urllib.request import urlopen  # stdlib to avoid extra deps


# A dynamic redaction spec: {"pattern": "regex", "tag": "secrets:vendor_token",
#                            "replacement": "[REDACTED:VENDOR_TOKEN]"}
_RedactionSpec = Dict[str, str]

# Compiled dynamic patterns: List[(compiled_re, tag, replacement)]
_DYNAMIC_PATTERNS: List[Tuple[re.Pattern[str], str, str]] = []


def threat_feed_enabled() -> bool:
    return os.getenv("THREAT_FEED_ENABLED", "false").lower() == "true"


def _fetch_json(url: str) -> Dict[str, Any]:
    with urlopen(url, timeout=10) as resp:  # nosec - controlled by admin/tests
        data = resp.read().decode("utf-8", "ignore")
        # mypy: json.loads returns Any; cast to Dict[str, Any] for our schema
        return cast(Dict[str, Any], json.loads(data))


def _compile_specs(
    specs: List[_RedactionSpec],
) -> List[Tuple[re.Pattern[str], str, str]]:
    compiled: List[Tuple[re.Pattern[str], str, str]] = []
    for s in specs:
        pat = s.get("pattern", "")
        tag = s.get("tag", "")
        repl = s.get("replacement", "")
        if not pat or not tag or not repl:
            continue
        try:
            compiled.append((re.compile(pat), tag, repl))
        except re.error:
            # skip bad pattern; feed robustness
            continue
    return compiled


def refresh_from_env() -> Dict[str, Any]:
    """
    Pull redaction specs from all URLs in THREAT_FEED_URLS (comma-separated),
    compile them, and replace the dynamic pattern set atomically.

    Expected JSON shape per URL:
      {
        "version": "2025-08-30",
        "redactions": [
          {
            "pattern": "token_[0-9]{6}",
            "tag": "secrets:vendor_token",
            "replacement": "[REDACTED:VENDOR_TOKEN]"
          }
        ]
      }
    """
    urls = [u.strip() for u in os.getenv("THREAT_FEED_URLS", "").split(",") if u.strip()]
    all_specs: List[_RedactionSpec] = []
    versions: List[str] = []

    for u in urls:
        try:
            doc = _fetch_json(u)
            versions.append(str(doc.get("version", "")))
            specs = doc.get("redactions", []) or []
            if isinstance(specs, list):
                all_specs.extend([s for s in specs if isinstance(s, dict)])
        except Exception:
            # ignore failing source; proceed with others
            continue

    compiled = _compile_specs(all_specs)

    # Swap atomically
    global _DYNAMIC_PATTERNS
    _DYNAMIC_PATTERNS = compiled

    return {
        "sources": len(urls),
        "loaded_specs": len(all_specs),
        "compiled": len(compiled),
        "versions": [v for v in versions if v],
    }


def apply_dynamic_redactions(
    text: str, debug: bool = False
) -> Tuple[str, List[str], int, List[Dict[str, Any]]]:
    """
    Apply dynamic patterns (if any). Returns:
      (sanitized_text, normalized_families, redaction_count, debug_matches)
    Families normalized to secrets:*, pi:*, payload:*, policy:deny:* (by prefix).
    """
    if not _DYNAMIC_PATTERNS:
        return text, [], 0, []

    out = text
    families: List[str] = []
    redactions = 0
    dbg: List[Dict[str, Any]] = []

    def _family(tag: str) -> str:
        if tag.startswith("secrets:"):
            return "secrets:*"
        if tag.startswith("pi:"):
            return "pi:*"
        if tag.startswith("payload:"):
            return "payload:*"
        if tag.startswith("policy:deny:"):
            return "policy:deny:*"
        return tag

    for pattern, tag, repl in _DYNAMIC_PATTERNS:
        matches = list(pattern.finditer(out))
        if not matches:
            continue
        out, n = pattern.subn(repl, out)
        redactions += n
        families.append(tag)
        if debug:
            for m in matches[:5]:
                dbg.append(
                    {
                        "tag": tag,
                        "span": {"start": m.start(), "end": m.end()},
                        "sample": out[max(0, m.start() - 8) : m.end() + 8],
                    }
                )

    # Deduplicate + normalize families
    nf = sorted({_family(t) for t in families})
    return out, nf, redactions, dbg

from __future__ import annotations

import re
from typing import Any, Dict, List

import yaml

Issue = Dict[str, Any]

# Guard against absurd regex length; compile will still run, but we flag it.
_MAX_REGEX_LEN = 10_000
# Reasonable upper bound for pack size we lint (bytes) to avoid abuse
_MAX_DOC_LEN = 1_000_000


def _ok() -> Dict[str, Any]:
    return {"status": "ok", "issues": []}


def _issue(sev: str, code: str, msg: str, path: str = "") -> Issue:
    return {"severity": sev, "code": code, "message": msg, "path": path}


def validate_yaml_text(yaml_text: str) -> Dict[str, Any]:
    """
    Validate a policy pack YAML string. Returns {"status": "ok"|"fail", "issues":[...]}.
    Does not mutate global state. Pure function.
    """
    issues: List[Issue] = []
    if not isinstance(yaml_text, str) or not yaml_text.strip():
        return {"status": "fail", "issues": [_issue("error", "empty", "No YAML provided")]}

    if len(yaml_text.encode("utf-8", "ignore")) > _MAX_DOC_LEN:
        issues.append(
            _issue(
                "warning",
                "oversize",
                "YAML document is very large; consider splitting",
            ),
        )

    try:
        doc = yaml.safe_load(yaml_text)
    except Exception as e:  # pragma: no cover - safety net
        return {
            "status": "fail",
            "issues": [
                _issue("error", "yaml_parse", f"YAML parse error: {type(e).__name__}: {e}"),
            ],
        }

    if not isinstance(doc, dict):
        issues.append(_issue("error", "schema.top", "Top-level YAML must be a mapping (object)"))

    # Version check
    version = None
    for key in ("policy_version", "version"):
        if isinstance(doc, dict):
            value = doc.get(key)
        else:
            value = None
        if value is not None:
            version = str(value)
            break
    if not version:
        issues.append(
            _issue(
                "warning",
                "version.missing",
                "Consider setting policy_version or version",
            ),
        )

    rules = doc.get("rules") if isinstance(doc, dict) else None
    if rules is not None and not isinstance(rules, dict):
        issues.append(_issue("error", "schema.rules", "'rules' must be an object"))

    redact = rules.get("redact") if isinstance(rules, dict) else None
    if redact is not None and not isinstance(redact, list):
        issues.append(_issue("error", "schema.redact", "rules.redact must be a list"))

    seen_ids = set()
    if isinstance(redact, list):
        for idx, entry in enumerate(redact):
            path = f"rules.redact[{idx}]"
            if not isinstance(entry, dict):
                issues.append(
                    _issue("error", "schema.redact.entry", "redact entry must be an object", path),
                )
                continue
            rid = entry.get("id")
            pat = entry.get("pattern") or entry.get("regex") or entry.get("re")
            if not rid:
                issues.append(_issue("error", "schema.redact.id", "missing 'id'", path))
            elif not isinstance(rid, str):
                issues.append(
                    _issue(
                        "error",
                        "schema.redact.id.type",
                        "'id' must be a string",
                        path,
                    ),
                )
            else:
                if rid in seen_ids:
                    issues.append(
                        _issue("error", "schema.redact.id.dup", f"duplicate id '{rid}'", path),
                    )
                seen_ids.add(rid)
            if not pat:
                issues.append(_issue("error", "schema.redact.pattern", "missing 'pattern'", path))
            elif not isinstance(pat, str):
                issues.append(
                    _issue(
                        "error",
                        "schema.redact.pattern.type",
                        "'pattern' must be a string",
                        path,
                    ),
                )
            else:
                if len(pat) > _MAX_REGEX_LEN:
                    issues.append(
                        _issue(
                            "warning",
                            "schema.redact.pattern.long",
                            "pattern is very long",
                            path,
                        ),
                    )
                try:
                    re.compile(pat)
                except re.error as exc:
                    issues.append(
                        _issue(
                            "error",
                            "schema.redact.pattern.invalid",
                            f"invalid regex: {exc}",
                            path,
                        ),
                    )

    status = "fail" if any(item["severity"] == "error" for item in issues) else "ok"
    return {"status": status, "issues": issues}

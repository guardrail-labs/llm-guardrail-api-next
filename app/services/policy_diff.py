from __future__ import annotations

from typing import Any, Dict, List


def _index_rules(doc: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    rules = (((doc or {}).get("rules") or {}).get("redact") or [])
    out: Dict[str, Dict[str, Any]] = {}
    for r in rules:
        rid = str((r or {}).get("id") or "").strip()
        if rid:
            out[rid] = dict(r)
    return out


def diff_policies(cur: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    cur_map = _index_rules(cur)
    new_map = _index_rules(new)

    added: List[Dict[str, Any]] = []
    removed: List[Dict[str, Any]] = []
    changed: List[Dict[str, Any]] = []

    cur_ids = set(cur_map.keys())
    new_ids = set(new_map.keys())

    for rid in sorted(new_ids - cur_ids):
        added.append({"id": rid, "rule": new_map[rid]})

    for rid in sorted(cur_ids - new_ids):
        removed.append({"id": rid, "rule": cur_map[rid]})

    for rid in sorted(cur_ids & new_ids):
        a, b = cur_map[rid], new_map[rid]
        fields = ("pattern", "replacement", "flags")
        diffs: Dict[str, Dict[str, Any]] = {}
        for field in fields:
            if a.get(field) != b.get(field):
                diffs[field] = {"from": a.get(field), "to": b.get(field)}
        if diffs:
            changed.append({"id": rid, "changes": diffs})

    return {
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "total_current": len(cur_map),
            "total_new": len(new_map),
        },
        "added": added,
        "removed": removed,
        "changed": changed,
    }

from __future__ import annotations

from typing import Any, Dict, Optional


def match(
    evt: Dict[str, Any],
    tenant: Optional[str] = None,
    bot: Optional[str] = None,
    family: Optional[str] = None,
    mode: Optional[str] = None,
    rule_id: Optional[str] = None,
    since: Optional[int] = None,
) -> bool:
    if tenant and evt.get("tenant") != tenant:
        return False
    if bot and evt.get("bot") != bot:
        return False
    if family and evt.get("family") != family:
        return False
    if mode and evt.get("mode") != mode:
        return False
    if since is not None:
        try:
            if int(evt.get("ts", 0)) < int(since):
                return False
        except Exception:
            return False
    if rule_id:
        rule_ids = evt.get("rule_ids") or []
        if rule_id not in rule_ids:
            return False
    return True

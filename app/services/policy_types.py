from __future__ import annotations

from typing import List, Literal, TypedDict

Action = Literal["allow", "lock", "deny"]


class PolicyResult(TypedDict, total=False):
    action: Action
    rule_ids: List[str]
    reason: str

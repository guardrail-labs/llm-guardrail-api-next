"""Typed response helpers for the Guardrail API client."""

from __future__ import annotations

from typing import Literal, Mapping, MutableMapping, Optional, Sequence, TypedDict


class DecisionItem(TypedDict, total=False):
    id: str
    ts: str
    tenant: str
    bot: str
    outcome: str
    policy_version: Optional[str]
    rule_id: Optional[str]
    incident_id: Optional[str]
    mode: Optional[str]
    details: Optional[Mapping[str, object]]


class DecisionPage(TypedDict, total=False):
    items: Sequence[DecisionItem]
    limit: int
    dir: Literal["next", "prev"]
    next_cursor: Optional[str]
    prev_cursor: Optional[str]
    total: Optional[int]
    page: Optional[int]
    page_size: Optional[int]


class AdjudicationItem(TypedDict, total=False):
    id: str
    ts: str
    tenant: str
    bot: str
    outcome: str
    rule_id: Optional[str]
    request_id: Optional[str]
    details: Optional[MutableMapping[str, object]]


class AdjudicationPage(TypedDict, total=False):
    items: Sequence[AdjudicationItem]
    limit: int
    dir: Literal["next", "prev"]
    next_cursor: Optional[str]
    prev_cursor: Optional[str]


__all__ = [
    "DecisionItem",
    "DecisionPage",
    "AdjudicationItem",
    "AdjudicationPage",
]

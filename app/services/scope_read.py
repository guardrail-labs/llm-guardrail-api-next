from __future__ import annotations

from typing import Dict, List, TypedDict


class PolicyPackInfo(TypedDict):
    name: str
    source: str
    version: str


class MitigationOverrideInfo(TypedDict):
    enabled: bool
    last_modified: int


def get_policy_packs(tenant: str, bot: str) -> List[PolicyPackInfo]:
    """Return normalized policy pack bindings for a tenant/bot pair."""

    return []


def get_mitigation_overrides(tenant: str, bot: str) -> Dict[str, MitigationOverrideInfo]:
    """Return mitigation overrides for a tenant/bot pair."""

    return {}


def get_secret_set_names(tenant: str, bot: str) -> List[str]:
    """Return secret set names available to a tenant/bot pair."""

    return []

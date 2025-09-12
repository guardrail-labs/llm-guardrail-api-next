from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(frozen=True)
class Binding:
    """
    Represents a routing/policy binding for a (tenant, bot).

    Fields:
      tenant_id: literal tenant ID or "*" wildcard
      bot_id:    literal bot ID or "*" wildcard
      policy_version: policy label/version string (non-empty)
      model: optional model/provider hint (purely informational here)
      priority: higher number wins when two bindings overlap
      source: optional provenance (file path, admin user, etc.)
    """
    tenant_id: str
    bot_id: str
    policy_version: str
    model: Optional[str] = None
    priority: int = 0
    source: Optional[str] = None

    @property
    def key(self) -> Tuple[str, str]:
        return (self.tenant_id, self.bot_id)

    @property
    def tenant_is_wildcard(self) -> bool:
        return self.tenant_id == "*"

    @property
    def bot_is_wildcard(self) -> bool:
        return self.bot_id == "*"

    def overlaps(self, other: "Binding") -> bool:
        """True if this binding could apply to the same request as `other`."""
        tenants_overlap = (
            self.tenant_id == other.tenant_id
            or self.tenant_is_wildcard
            or other.tenant_is_wildcard
        )
        bots_overlap = (
            self.bot_id == other.bot_id or self.bot_is_wildcard or other.bot_is_wildcard
        )
        return tenants_overlap and bots_overlap

    def identical_target(self, other: "Binding") -> bool:
        """True if both bindings target the exact same tuple (no wildcards)."""
        return self.tenant_id == other.tenant_id and self.bot_id == other.bot_id

    def semantically_equal(self, other: "Binding") -> bool:
        """True if both bindings encode the same outcome."""
        return (
            self.policy_version == other.policy_version
            and (self.model or "") == (other.model or "")
        )


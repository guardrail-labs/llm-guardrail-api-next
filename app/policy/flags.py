from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Literal, Optional

Action = Literal["off", "flag", "escape", "clarify", "block"]


@dataclass(frozen=True)
class SanitizerFlags:
    enable_normalize: bool = True
    strip_zero_width: bool = True
    escape_bidi: bool = True
    confusables_action: Action = "flag"
    max_confusables_ratio: float = 0.05


def get_tenant_id_from_headers(header_get: Callable[[str], Optional[str]]) -> str:
    tenant = header_get("x-tenant")
    return tenant or "default"


def get_sanitizer_flags(tenant_id: Optional[str] = None) -> SanitizerFlags:
    return SanitizerFlags()

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Literal, Optional

Action = Literal["off", "flag", "clarify", "block"]


@dataclass(frozen=True)
class MultimodalFlags:
    enabled: bool = True
    max_bytes: int = 5 * 1024 * 1024  # 5 MiB per part
    action: Action = "flag"


def get_tenant_id_from_headers(header_get: Callable[[str], Optional[str]]) -> str:
    tenant = header_get("x-tenant")
    return tenant or "default"


def get_multimodal_flags(tenant_id: Optional[str] = None) -> MultimodalFlags:
    # Minimal stub; future: load per-tenant config.
    return MultimodalFlags()

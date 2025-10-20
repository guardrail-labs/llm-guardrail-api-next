from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class AuditRecord:
    ts: str
    tenant: str
    request_id: str
    incident_id: Optional[str]
    decision: str
    mode: str
    headers: Dict[str, str]
    payload: Dict[str, Any]


class AuditStore:
    """Read-only provider for audit events."""

    def query(
        self,
        tenant: str,
        start_iso: Optional[str] = None,
        end_iso: Optional[str] = None,
        incident_id: Optional[str] = None,
        limit: int = 10_000,
    ) -> List[AuditRecord]:
        raise NotImplementedError

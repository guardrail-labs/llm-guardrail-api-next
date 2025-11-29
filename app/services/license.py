from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Optional


class LicenseStatusCode(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    INVALID = "invalid"
    MISSING = "missing"
    UNKNOWN = "unknown"
    ERROR = "error"


@dataclass
class LicenseStatus:
    status: LicenseStatusCode
    plan: Optional[str] = None
    message: str = ""
    last_checked_at: Optional[datetime] = None

    def as_dict(self) -> Dict[str, object]:
        return {
            "status": self.status.value,
            "plan": self.plan,
            "message": self.message,
            "last_checked_at": (self.last_checked_at.isoformat() if self.last_checked_at else None),
        }


@dataclass
class LicenseState:
    """
    Simple in-memory holder for the current license status.

    This is intentionally minimal for now. In a later phase we will:
    - Add periodic background verification.
    - Integrate with a remote license verification service.
    - Optionally enforce blocking behavior when status is not ACTIVE.
    """

    _current: LicenseStatus = field(
        default_factory=lambda: LicenseStatus(
            status=LicenseStatusCode.UNKNOWN,
            plan=None,
            message="License status has not been checked yet.",
            last_checked_at=None,
        ),
    )

    def get(self) -> LicenseStatus:
        return self._current

    def set(self, status: LicenseStatus) -> None:
        self._current = status


license_state = LicenseState()


def initialize_license_from_env(license_key: Optional[str]) -> None:
    """
    Basic, non-enforcing initialization:

    - If no license key is provided, set status to MISSING.
    - If a license key is provided, set status to UNKNOWN. In later phases,
      this will trigger a real verification call.
    """
    now = datetime.now(timezone.utc)

    if not license_key:
        license_state.set(
            LicenseStatus(
                status=LicenseStatusCode.MISSING,
                plan=None,
                message="GUARDRAIL_LICENSE_KEY is not set.",
                last_checked_at=now,
            ),
        )
        return

    license_state.set(
        LicenseStatus(
            status=LicenseStatusCode.UNKNOWN,
            plan=None,
            message="License key is configured but has not been verified.",
            last_checked_at=now,
        ),
    )

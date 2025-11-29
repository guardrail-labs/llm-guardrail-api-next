from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Optional

from app.net.http_client import get_http_client


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


@dataclass
class _RemoteLicenseResponse:
    status: str
    plan: Optional[str] = None
    subscription_id: Optional[str] = None
    subscription_status: Optional[str] = None
    message: str = ""
    limits: Optional[Dict[str, object]] = None


def _redact_license_key(license_key: str) -> str:
    if len(license_key) <= 8:
        return "***redacted***"
    return f"{license_key[:4]}****{license_key[-4:]}"


def _map_remote_status(status: str) -> LicenseStatusCode:
    mapping = {
        "active": LicenseStatusCode.ACTIVE,
        "revoked": LicenseStatusCode.REVOKED,
        "invalid": LicenseStatusCode.INVALID,
        "missing": LicenseStatusCode.MISSING,
        "unknown": LicenseStatusCode.UNKNOWN,
    }
    return mapping.get(status.lower(), LicenseStatusCode.ERROR)


async def refresh_license_from_remote(
    license_key: Optional[str],
    verify_url: Optional[str],
    timeout_seconds: int,
    instance_id: Optional[str] = None,
    runtime: str = "core",
) -> None:
    """
    If license_key and verify_url are configured, call the central license
    verification API and update the in-memory license_state accordingly.

    This function must NOT raise. All errors should be caught and reflected
    in license_state as ERROR, with a short message.
    """

    log = logging.getLogger(__name__)

    if not license_key or not verify_url:
        return

    payload: Dict[str, object] = {
        "license_key": license_key,
        "runtime": runtime,
        "instance_id": instance_id,
    }
    now = datetime.now(timezone.utc)

    try:
        client = get_http_client()
        response = await client.post(
            verify_url,
            json=payload,
            timeout=timeout_seconds,
        )
        if response.status_code == 200:
            try:
                data = response.json()
            except Exception as exc:  # pragma: no cover - defensive
                raise ValueError(f"invalid JSON response: {exc}") from exc
            if not isinstance(data, dict):
                raise ValueError("unexpected response payload")
            remote = _RemoteLicenseResponse(
                status=str(data.get("status", "error")),
                plan=data.get("plan"),
                subscription_id=data.get("subscription_id"),
                subscription_status=data.get("subscription_status"),
                message=str(data.get("message", "")),
                limits=data.get("limits"),
            )
            mapped_status = _map_remote_status(remote.status)
            license_state.set(
                LicenseStatus(
                    status=mapped_status,
                    plan=remote.plan,
                    message=remote.message or "License verification completed.",
                    last_checked_at=now,
                )
            )
            return

        message = f"Error verifying license: HTTP {response.status_code}"
        log.error(
            "License verification failed: %s (key=%s)",
            message,
            _redact_license_key(license_key),
        )
    except Exception as exc:  # pragma: no cover - defensive
        message = f"Error verifying license: {exc}"  # noqa: B904
        log.error(
            "License verification exception: %s (key=%s)",
            exc,
            _redact_license_key(license_key),
        )

    license_state.set(
        LicenseStatus(
            status=LicenseStatusCode.ERROR,
            plan=None,
            message=message,
            last_checked_at=now,
        )
    )


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

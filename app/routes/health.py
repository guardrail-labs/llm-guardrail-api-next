from __future__ import annotations

from fastapi import APIRouter

from app.telemetry.metrics import (
    get_requests_total,
    get_decisions_total,
    get_rules_version,
)
from app.services.policy import current_rules_version
from app.services.detectors.ingress_pipeline import _enabled as _flag_enabled

router = APIRouter(prefix="/health", tags=["system"])

# Separate router without prefix for /healthz
router_healthz = APIRouter(tags=["system"])


@router.get("")
def health() -> dict[str, object]:
    return {
        "ok": True,
        "status": "ok",
        "requests_total": float(get_requests_total()),
        "decisions_total": float(get_decisions_total()),
        "rules_version": str(get_rules_version()),
    }


@router_healthz.get("/healthz")
def healthz() -> dict[str, object]:
    """Lightweight healthcheck reflecting feature flags."""
    return {
        "status": "ok",
        "policy_version": str(current_rules_version()),
        "features": {
            "pdf_detector": _flag_enabled("PDF_DETECTOR_ENABLED", True),
            "docx_detector": _flag_enabled("DOCX_DETECTOR_ENABLED", True),
            "image_safe_transform": _flag_enabled(
                "IMAGE_SAFE_TRANSFORM_ENABLED", True
            ),
        },
    }

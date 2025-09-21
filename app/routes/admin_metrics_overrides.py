from __future__ import annotations

import importlib
import os
import time
from types import ModuleType
from typing import Dict, Optional

from fastapi import APIRouter, Depends
from prometheus_client import REGISTRY, CollectorRegistry
from prometheus_client.samples import Sample
from pydantic import BaseModel

from app.observability.metrics import mitigation_override_counter  # noqa: F401
from app.routes.admin_mitigation import require_admin_session

router = APIRouter(prefix="/admin/api/metrics", tags=["admin-metrics"])
_PROCESS_START_MS = int(time.time() * 1000)


class MitigationTotals(BaseModel):
    block: int
    clarify: int
    redact: int


class OverridesResp(BaseModel):
    totals: MitigationTotals
    since_ms: int


def _load_multiprocess() -> Optional[ModuleType]:
    try:
        return importlib.import_module("prometheus_client.multiprocess")
    except Exception:  # pragma: no cover
        return None


multiprocess = _load_multiprocess()


def _active_registry() -> CollectorRegistry:
    """Return the registry that reflects process-wide metrics."""

    mp_dir = os.getenv("PROMETHEUS_MULTIPROC_DIR")
    if mp_dir and multiprocess is not None:
        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry)
        return registry
    return REGISTRY


def _collect_totals() -> Dict[str, int]:
    totals: Dict[str, int] = {"block": 0, "clarify": 0, "redact": 0}
    registry = _active_registry()
    try:
        collections = registry.collect()
    except Exception:
        return totals

    for metric in collections:
        samples = getattr(metric, "samples", [])
        for sample in samples:
            if (
                isinstance(sample, Sample)
                and sample.name == "guardrail_mitigation_override_total"
            ):
                mode = (sample.labels or {}).get("mode")
                if mode in totals:
                    try:
                        totals[mode] += int(sample.value)
                    except Exception:
                        continue
    return totals


@router.get("/mitigation-overrides", response_model=OverridesResp)
def get_mitigation_overrides(_: None = Depends(require_admin_session)) -> OverridesResp:
    totals = _collect_totals()
    return OverridesResp(totals=MitigationTotals(**totals), since_ms=_PROCESS_START_MS)

from __future__ import annotations

import time

from fastapi import APIRouter, Depends
from prometheus_client.samples import Sample
from pydantic import BaseModel

from app.observability.metrics import mitigation_override_counter
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


def _collect_totals() -> dict[str, int]:
    totals: dict[str, int] = {"block": 0, "clarify": 0, "redact": 0}
    try:
        collections = mitigation_override_counter.collect()
    except Exception:
        return totals

    for metric in collections:
        samples = getattr(metric, "samples", [])
        for sample in samples:
            if isinstance(sample, Sample) and sample.name == "guardrail_mitigation_override_total":
                mode = sample.labels.get("mode") if sample.labels else None
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

from __future__ import annotations

import time
from typing import Iterable

from fastapi import APIRouter, Depends
from prometheus_client.samples import Sample
from pydantic import BaseModel

from app.observability.metrics import mitigation_override_counter
from app.routes.admin_mitigation import require_admin_session

router = APIRouter(
    prefix="/admin/api/metrics",
    tags=["admin-metrics"],
    dependencies=[Depends(require_admin_session)],
)

_PROCESS_START_MS = int(time.time() * 1000)


class MitigationTotals(BaseModel):
    block: int
    clarify: int
    redact: int


class OverridesResp(BaseModel):
    totals: MitigationTotals
    since_ms: int


def _counter_totals_by_mode() -> MitigationTotals:
    values: dict[str, int] = {"block": 0, "clarify": 0, "redact": 0}
    try:
        collections = mitigation_override_counter.collect()
    except Exception:
        return MitigationTotals(**values)

    for metric in collections:
        samples: Iterable[Sample] = getattr(metric, "samples", ()) or ()
        for sample in samples:
            if not isinstance(sample, Sample):
                continue
            if sample.name != "guardrail_mitigation_override_total":
                continue
            mode = sample.labels.get("mode")
            if mode in values:
                try:
                    values[mode] += int(sample.value)
                except Exception:
                    continue
    return MitigationTotals(**values)


@router.get("/mitigation-overrides", response_model=OverridesResp)
def get_mitigation_overrides() -> OverridesResp:
    totals = _counter_totals_by_mode()
    return OverridesResp(totals=totals, since_ms=_PROCESS_START_MS)

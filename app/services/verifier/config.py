from __future__ import annotations

import os
from typing import Optional


def get_verifier_latency_budget_ms() -> Optional[int]:
    raw = os.getenv("VERIFIER_LATENCY_BUDGET_MS", "").strip()
    if not raw:
        return None
    try:
        v = int(raw)
        return v if v > 0 else None
    except ValueError:
        return None

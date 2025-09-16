from __future__ import annotations

import json
import os
import time
from typing import Any, Mapping, Optional

from .config_store import get_config


def _load_policy_blob(path: str) -> Optional[Mapping[str, Any]]:
    try:
        expanded = os.path.expanduser(path)
        with open(expanded, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, Mapping):
            return data
    except Exception:
        return None
    return None


def maybe_eval_shadow(
    payload: Mapping[str, Any],
    live_action: str,
    route: str,
    evaluator,
) -> Optional[Mapping[str, Any]]:
    cfg = get_config()
    if not bool(cfg.get("shadow_enable", False)):
        return None

    try:
        sr = float(cfg.get("shadow_sample_rate", 1.0))
    except Exception:
        sr = 1.0
    if sr < 1.0:
        try:
            import random

            if random.random() > max(0.0, min(1.0, sr)):
                return None
        except Exception:
            pass

    path_val = cfg.get("shadow_policy_path")
    if not path_val:
        return None
    policy = _load_policy_blob(str(path_val))
    if not policy:
        return None

    try:
        budget_ms = int(cfg.get("shadow_timeout_ms", 100))
    except Exception:
        budget_ms = 100
    if budget_ms <= 0:
        budget_ms = 100

    start = time.time()
    try:
        result = evaluator(payload, policy=policy)
    except Exception:
        return None

    if not isinstance(result, Mapping):
        return None

    latency_ms = int(max((time.time() - start) * 1000.0, 0.0))
    result = dict(result)
    result.setdefault("_shadow_ts", int(time.time()))
    result.setdefault("_shadow_latency_ms", latency_ms)
    result.setdefault("_shadow_budget_ms", budget_ms)
    result.setdefault("_shadow_live_action", live_action)
    result.setdefault("_shadow_route", route)
    return result

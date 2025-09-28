#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Tuple, cast

BASELINE = Path("bench/baseline/egress.json")
LAST = Path("bench/results/last.json")


def _load(path: Path) -> Dict[str, Any]:
    return cast(Dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _to_map(obj: Dict[str, Any]) -> Dict[str, Dict[str, float]]:
    mapping: Dict[str, Dict[str, float]] = {}
    for scenario in obj.get("scenarios", []):
        mapping[scenario["id"]] = {"p95": float(scenario.get("p95", 0.0))}
    return mapping


def compare(threshold: float) -> Tuple[bool, str]:
    if not BASELINE.exists() or not LAST.exists():
        return True, "baseline or last.json missing; skipping compare"
    base = _load(BASELINE)
    if not base.get("locked", False):
        return True, "baseline not locked; skipping compare"
    current = _load(LAST)
    baseline_map = _to_map(base)
    current_map = _to_map(current)
    regressions = []
    for scenario_id, baseline_vals in baseline_map.items():
        if scenario_id not in current_map:
            continue
        baseline_p95 = baseline_vals["p95"]
        current_p95 = current_map[scenario_id]["p95"]
        if baseline_p95 > 0 and current_p95 > baseline_p95 * (1.0 + threshold):
            regressions.append((scenario_id, baseline_p95, current_p95))
    if regressions:
        lines = ["Perf regression over threshold:"]
        for scenario_id, baseline_p95, current_p95 in regressions:
            lines.append(
                (
                    f"{scenario_id}: p95 {current_p95:.6f}s > "
                    f"{baseline_p95:.6f}s * (1+{threshold:.2f})"
                )
            )
        return False, "\n".join(lines)
    return True, "No regressions beyond threshold"


def _main() -> int:
    threshold = float(os.environ.get("BENCH_THRESHOLD", "0.25"))
    ok, message = compare(threshold)
    print(message)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(_main())

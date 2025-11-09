#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, Optional, cast

JSONDict = Dict[str, Any]


def pick_all_bucket(rows: Any) -> Optional[JSONDict]:
    """Return the 'ALL' bucket dict from a results list, or None if absent."""
    if not isinstance(rows, list):
        return None
    for r in rows:
        if isinstance(r, dict) and r.get("name") == "ALL":
            return cast(JSONDict, r)
    return None


def load(path: str) -> JSONDict:
    """Load a JSON file and assert a top-level object (dict)."""
    with open(path, "r", encoding="utf-8") as f:
        data: Any = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a top-level JSON object")
    return cast(JSONDict, data)


def percent_change(new: float, old: float) -> float:
    """
    Percentage change from old -> new, i.e. (new - old) / old * 100.
    Positive means an increase vs baseline; negative means a decrease.
    """
    if old == 0.0:
        return 0.0 if new == 0.0 else float("inf")
    return (new - old) / old * 100.0


def require_field(r: JSONDict, key: str) -> float:
    """Fetch numeric field from a result row, raising if missing."""
    val = r.get(key)
    if val is None:
        raise ValueError(f"Missing '{key}' in result row")
    return float(val)


def main() -> int:
    ap = argparse.ArgumentParser(description="Compare bench results against baseline")
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--result", required=True)
    ap.add_argument("--max-p95-reg-pct", type=float, default=20.0)
    ap.add_argument("--max-rps-drop-pct", type=float, default=20.0)
    ap.add_argument("--min-success-rate", type=float, default=99.0)
    args = ap.parse_args()

    base = load(args.baseline)
    res = load(args.result)

    b_all = pick_all_bucket(base.get("results"))
    r_all = pick_all_bucket(res.get("results"))
    if b_all is None or r_all is None:
        print(
            "Could not find ALL bucket in baseline/result",
            file=sys.stderr,
        )
        return 2

    # Pull metrics
    b_p95 = require_field(b_all, "p95_ms")
    r_p95 = require_field(r_all, "p95_ms")
    b_rps = require_field(b_all, "rps")
    r_rps = require_field(r_all, "rps")
    r_ok = require_field(r_all, "success_rate")

    # p95 regression: percent increase vs. baseline
    p95_reg_pct = percent_change(r_p95, b_p95)

    # rps drop: percent decrease vs. baseline (positive number when result is lower)
    rps_change_pct = percent_change(r_rps, b_rps)  # negative if result < baseline
    rps_drop_pct = max(0.0, -rps_change_pct)

    print("=== Perf Regression Check (ALL) ===")
    print(f"Baseline p95_ms={b_p95}  Result p95_ms={r_p95}  Δ%={p95_reg_pct:.2f}")
    print(f"Baseline rps={b_rps}     Result rps={r_rps}     Drop%={rps_drop_pct:.2f}")
    print(f"Result success_rate={r_ok:.2f}% (min {args.min_success_rate}%)")

    failures = []
    if r_ok < args.min_success_rate:
        failures.append(f"success_rate {r_ok:.2f}% < {args.min_success_rate}%")
    if p95_reg_pct > args.max_p95_reg_pct:
        failures.append(f"p95 regression {p95_reg_pct:.2f}% > {args.max_p95_reg_pct}%")
    if rps_drop_pct > args.max_rps_drop_pct:
        failures.append(f"rps drop {rps_drop_pct:.2f}% > {args.max_rps_drop_pct}%")

    if failures:
        print("FAIL: " + "; ".join(failures), file=sys.stderr)
        return 1

    print("OK: within thresholds")
    return 0


if __name__ == "__main__":
    sys.exit(main())

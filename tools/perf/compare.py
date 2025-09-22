#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, sys
from typing import Any, Dict, Optional

def pick_all_bucket(rows: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(rows, list):
        return None
    for r in rows:
        if isinstance(r, dict) and r.get("name") == "ALL":
            return r
    return None

def load(path: str) -> Dict[str, Any]:
    with open(path, "r") as f:
        return json.load(f)

def percent_change(new: float, old: float) -> float:
    if old == 0:
        return 0.0 if new == 0 else float("inf")
    return (new - old) / old * 100.0

def require_field(r: Dict[str, Any], key: str) -> float:
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
    if not b_all or not r_all:
        print("Could not find ALL bucket in baseline/result", file=sys.stderr)
        return 2

    # pull metrics
    b_p95 = require_field(b_all, "p95_ms")
    r_p95 = require_field(r_all, "p95_ms")
    b_rps = require_field(b_all, "rps")
    r_rps = require_field(r_all, "rps")
    r_ok  = require_field(r_all, "success_rate")

    p95_reg_pct = percent_change(r_p95, b_p95)
    rps_drop_pct = percent_change(b_rps, r_rps)  # drop if result lower

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

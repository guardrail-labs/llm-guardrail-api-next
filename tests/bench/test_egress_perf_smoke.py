from __future__ import annotations

import os

from bench.egress_bench import run as bench_run


def test_smoke_bench_runs_fast() -> None:
    result = bench_run()
    assert result["scenarios"], "no scenarios produced"
    keys = {"id", "p95", "bytes", "runs"}
    for scenario in result["scenarios"]:
        assert keys.issubset(scenario.keys())


def test_compare_against_baseline_if_locked() -> None:
    if not os.environ.get("BENCH_COMPARE"):
        return
    from bench.compare import compare

    threshold = float(os.environ.get("BENCH_THRESHOLD", "0.25"))
    ok, _ = compare(threshold)
    if os.environ.get("BENCH_ENFORCE"):
        assert ok, "perf regression over threshold"

# Egress micro-bench (peek + redactor)

## Run locally
```bash
python bench/egress_bench.py
# results → bench/results/egress_<ts>.json and bench/results/last.json
```

## Establish a baseline

1. Run the bench on a clean machine/runner.
2. Copy `bench/results/last.json` → `bench/baseline/egress.json`.
3. Edit the baseline to set `"locked": true`.
4. Commit the updated baseline.

## Compare in CI (env-gated)

Set `BENCH_COMPARE=1` to compare `results/last.json` to the baseline.

Set `BENCH_ENFORCE=1` to fail on regressions.

Adjust the threshold with `BENCH_THRESHOLD` (default `0.25` = 25%).

Example:

```bash
BENCH_COMPARE=1 BENCH_ENFORCE=1 BENCH_THRESHOLD=0.30 pytest -q
```

## Notes

- Scenarios are intentionally light (256KB, 5 runs) for CI.
- Tune sizes/chunks in `bench/egress_bench.py` for deeper runs offline.

## Dev commands (Codex should run)
```bash
ruff check --fix .
ruff format .
mypy --check-untyped-defs .

pytest tests/bench/test_egress_perf_smoke.py -q
pytest -q
```

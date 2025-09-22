# Perf Baselines

Nightly job runs `tools/perf/bench.py` and optionally compares results to a committed baseline.

- Baseline path (by default): `perf/baseline.json`
- To set a baseline:
  1. Run the bench locally or via the RC release workflow:
     ```
     python tools/perf/bench.py --base https://rc.example.com -c 50 -d 60s --out perf/baseline.json
     ```
  2. Commit `perf/baseline.json` to the repo.

## Thresholds

Edit `.github/workflows/perf-nightly.yml` env values in the "Compare vs baseline" step:

- `MAX_P95_REG_PCT` (default 20)
- `MAX_RPS_DROP_PCT` (default 20)
- `MIN_SUCCESS_RATE` (default 99)

If `perf/baseline.json` is missing, the nightly job will still run and upload the JSON, but skip the comparison.

(No baseline file is committed by default to avoid flaky failure before you capture RC1 numbers.)

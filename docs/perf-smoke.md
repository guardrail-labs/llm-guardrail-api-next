# Perf smoke & baselines

## 1) Run the smoke
```bash
make perf-smoke-run
```

## 2) Compare to a baseline
```bash
uv run python tools/perf/compare.py \
  --baseline out-baseline.json \
  --candidate out-smoke.json
```

The comparator:
- Computes RPS drops **relative to baseline**.
- Clamps negative math to positive “drop” properly.
- Emits a short human summary and JSON.

## CI artifacts
The perf smoke job uploads JSON so you can attach them to the RC release. See:
- `Actions → perf-smoke` run artifacts
- [`docs/release-checklist.md`](docs/release-checklist.md)

For the pre-RC artifact helper (writes `perf-rc-candidate.json`), run `make perf-smoke`.

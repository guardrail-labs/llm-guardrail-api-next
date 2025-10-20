# Bench Harness (Core)

Run mixed-traffic load against a target Guardrail API deployment and produce:
- JSON results (latency p50/p95/p99, RPS, error rate, clarify/block shares)
- Markdown report
- Optional scrape of `/metrics` for sanitizer/verifier counters

## Quick start
```bash
# env
export BENCH_BASE_URL="http://localhost:8000"
export BENCH_METRICS_URL="http://localhost:8000/metrics"  # optional
# run default scenario set
scripts/run_bench.sh
# run a specific scenario
python -m bench.runner --scenario basic_mixed --duration 60 --workers 16
```

See docs/SLOs.md for targets and reading the report.

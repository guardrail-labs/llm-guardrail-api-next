# Performance Baseline (Smoke)

This simple, repeatable smoke test measures aggregate and per-endpoint RPS/latency.
It is **not** a full load test—just a quick health/perf check to compare before/after changes.

## How to run

```bash
# Local dev (defaults to http://localhost:8000)
make perf-smoke

# Against a deployed env
BASE="https://your-env.example.com" TOKEN="...scoped-service-token..." C=80 DURATION=90s make perf-smoke

# Save JSON
OUT=perf-$(date +%Y%m%d-%H%M).json make perf-smoke
```

Flags (via env):

BASE (default: http://localhost:8000)

TOKEN (optional; adds Authorization: Bearer <TOKEN>)

C concurrency (default: 50)

DURATION (default: 60s)

TIMEOUT (default: 5)

LIMIT decisions page size (default: 50)

INSECURE set to any non-empty value to disable TLS verify

## Recommended Baseline Capture

Record one run per environment (dev/stage/prod) after deployment.

Image/tag: ghcr.io/...:<tag>

Flags: C=<N> DURATION=<T>

Results (copy/paste from script):

ALL | reqs=... rps=... p50=...ms p95=...ms p99=...ms ok=...%

healthz | ...

readyz | ...

decisions | ...

Add brief context: node size, replicas, Redis tier. Commit this file after each RC as an audit trail.

---

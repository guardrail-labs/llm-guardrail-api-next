# Observability

## Endpoints
- **Prometheus**: `/metrics` (exposed by existing Prom integration)
- **Health**: `GET /health`

## Key Metrics (emitted by app)
- `guardrail_latency_seconds{route,method}` — existing histogram
- `guardrail_clarify_total{phase}` — total clarify-first decisions (phase: ingress)
- `guardrail_egress_redactions_total{tenant,bot,kind}` — redactions applied (json/text)

> Counters are monotonic; use `rate()` or `increase()` over a window.

## PromQL Recipes

### 1) P95 latency by route (5m window)


histogram_quantile(
0.95,
sum(rate(guardrail_latency_seconds_bucket[5m])) by (le, route)
)


### 2) Clarify rate (per minute)


sum(rate(guardrail_clarify_total[1m]))


### 3) Redactions rate by kind (5m)


sum(rate(guardrail_egress_redactions_total[5m])) by (kind)


### 4) Clarify % of total requests (approx)


sum(rate(guardrail_clarify_total[5m]))
/
sum by (route) (rate(guardrail_latency_seconds_count[5m]))


## Grafana
Import `dashboards/grafana_guardrail.json` → set your Prometheus datasource.

### Streaming Redactions

Incremental redactions performed during SSE/chunked responses increment:

- `guardrail_egress_redactions_total{tenant="<t>",bot="<b>",kind="text/stream"}`

**PromQL (rate over 5m):**

sum(rate(guardrail_egress_redactions_total{kind="text/stream"}[5m]))

### Rulepack Enforcement
- Egress redactions from rulepacks are merged with built-ins when `RULEPACKS_ENFORCE=1` and `RULEPACKS_EGRESS_MODE=enforce`.
- Ingress rulepacks can trigger clarify/block if `RULEPACKS_INGRESS_MODE` is set.
- See README for env toggles.


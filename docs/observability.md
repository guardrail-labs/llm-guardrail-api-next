# Observability

## Endpoints
- **Prometheus**: `/metrics` (exposed by existing Prom integration)
- **Health**: `GET /health`

## Key Metrics (emitted by app)
- `guardrail_latency_seconds{route,method}` — existing histogram
- `guardrail_clarify_total{phase}` — total clarify-first decisions (phase: ingress)
- `guardrail_egress_redactions_total{content_type}` — redactions applied (json/text)

> Counters are monotonic; use `rate()` or `increase()` over a window.

## PromQL Recipes

### 1) P95 latency by route (5m window)


histogram_quantile(
0.95,
sum(rate(guardrail_latency_seconds_bucket[5m])) by (le, route)
)


### 2) Clarify rate (per minute)


sum(rate(guardrail_clarify_total[1m]))


### 3) Redactions rate by content type (5m)


sum(rate(guardrail_egress_redactions_total[5m])) by (content_type)


### 4) Clarify % of total requests (approx)


sum(rate(guardrail_clarify_total[5m]))
/
sum by (route) (rate(guardrail_latency_seconds_count[5m]))


## Grafana
Import `dashboards/grafana_guardrail.json` → set your Prometheus datasource.


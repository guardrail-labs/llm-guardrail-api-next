# Guardrail API — PromQL Snippets

> Assumes default metric names exported by the app. Adjust job/instance labels for your scrape config.

## 1) Request Volume & Decisions

**Total request rate (req/s)**

sum(rate(guardrail_requests_total[5m]))


**Allow vs block (decisions/s)**

sum by (family) (rate(guardrail_decisions_total[5m]))


## 2) Latency

**p50 / p95 / p99 latency (ms) by endpoint**

1000 * histogram_quantile(0.50, sum by (le, endpoint) (rate(guardrail_latency_seconds_bucket[5m])))
1000 * histogram_quantile(0.95, sum by (le, endpoint) (rate(guardrail_latency_seconds_bucket[5m])))
1000 * histogram_quantile(0.99, sum by (le, endpoint) (rate(guardrail_latency_seconds_bucket[5m])))


> Note: If your build exports HTTP status counters (e.g., `guardrail_http_status_total{status=...}`), re-enable the 5xx/429 queries accordingly.


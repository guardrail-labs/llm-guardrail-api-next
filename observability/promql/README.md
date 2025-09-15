# Guardrail API — PromQL Snippets

> Assumes default metric names exported by the app. Adjust job/instance labels for your scrape config.

## 1) Request Volume & Outcome

**Total request rate (req/s)**  

sum by (route) (rate(guardrail_requests_total[5m]))


**Block vs allow rate**  

sum by (action) (rate(guardrail_requests_total{action=~"allow|block"}[5m]))


**Block percentage**  

100 * sum(rate(guardrail_requests_total{action="block"}[5m]))
/ sum(rate(guardrail_requests_total[5m]))


## 2) Latency

**p50 / p95 / p99 latency (ms) per route**  

histogram_quantile(0.50, sum by (le, route) (rate(guardrail_request_latency_ms_bucket[5m])))
histogram_quantile(0.95, sum by (le, route) (rate(guardrail_request_latency_ms_bucket[5m])))
histogram_quantile(0.99, sum by (le, route) (rate(guardrail_request_latency_ms_bucket[5m])))


**Verifier latency (if exposed as separate histogram)**  

histogram_quantile(0.95, sum by (le, provider) (rate(guardrail_verifier_latency_ms_bucket[5m])))


## 3) Errors & Rate Limits

**5xx rate**  

sum(rate(guardrail_requests_total{status=~"5.."}[5m]))


**429 rate (throttling/quarantine)**  

sum(rate(guardrail_requests_total{status="429"}[5m]))


## 4) Metrics Cardinality Overflow

**Overflow share for tenant×bot labels**  
> Uses a stable sentinel label `__overflow__` after the cap.


100 * sum(rate(guardrail_requests_total{tenant="overflow"}[5m]))
/ sum(rate(guardrail_requests_total[5m]))


If you expose both `tenant` and `bot` limited via a helper, also check bot:


100 * sum(rate(guardrail_requests_total{bot="overflow"}[5m]))
/ sum(rate(guardrail_requests_total[5m]))


## 5) Policy Version Mix

**Active policy versions (last 15m)**  

count by (policy_version) (sum_over_time(guardrail_requests_total[15m]) > 0)


## 6) SLO Burn (example)

**Latency SLO (p95 < 300ms) error budget burn**  

histogram_quantile(0.95, sum by (le) (rate(guardrail_request_latency_ms_bucket[5m]))) > 300

Use in an alert with for: 10m to avoid flaps.


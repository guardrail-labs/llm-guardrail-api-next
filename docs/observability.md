# Observability — Guardrail API

This guide ships a turnkey set of PromQL queries, a Grafana dashboard, and Prometheus alert rules.

## Prereqs
- Prometheus scraping the app (e.g., `/metrics`)
- Grafana with access to the same Prometheus datasource

## Quickstart

1) **Import Dashboard**
- Grafana → Dashboards → Import
- Upload `observability/grafana/guardrail.json`
- Choose your Prometheus datasource; save.

2) **Load Alert Rules**
- Copy `observability/alerts/guardrail-rules.yaml` into your Prometheus rules directory.
- Reference it in `prometheus.yml`:
  ```yaml
  rule_files:
    - "rules/*.yaml"
    - "observability/alerts/guardrail-rules.yaml"


Reload Prometheus or restart the service.

Explore PromQL

See observability/promql/README.md for queries you can paste directly into Grafana Explore.

Key Metrics & Notes

guardrail_requests_total{endpoint}

Counter for incoming requests by endpoint.

guardrail_decisions_total{family}

Counter for decisions such as allow or deny.

guardrail_latency_seconds_bucket

Histogram for request latency in seconds; multiply by 1000 for milliseconds.

guardrail_verifier_latency_seconds_bucket (if enabled)

Histogram per provider for verifier calls.

Cardinality Guard

We cap (tenant×bot) label combinations; overflow sentinel is __overflow__.

Tune via METRICS_LABEL_CARD_MAX.

SLO Examples

Availability: error_rate < 1% over rolling 30d

100 * sum(rate(guardrail_requests_total{status=~"5.."}[5m])) / sum(rate(guardrail_requests_total[5m])) < 1


Latency: p95 < 300ms

1000 * histogram_quantile(0.95, sum by (le) (rate(guardrail_latency_seconds_bucket[5m]))) < 300

Troubleshooting

No data in panels: verify the job label (job="guardrail") or remove label selectors in queries.

Overflow % high: increase METRICS_LABEL_CARD_MAX or validate tenant/bot churn.

429 spikes: review rate limits/quarantine thresholds and traffic patterns.

### Multi-tenant labels

Requests can supply headers:
- `X-Tenant`: logical tenant/org identifier
- `X-Bot`: calling bot/service identifier

We emit `guardrail_actor_decisions_total{family,tenant,bot}` and cap `(tenant×bot)` label cardinality using `METRICS_LABEL_CARD_MAX`. Values beyond the cap collapse to `__overflow__`.

> Tip: Use the demo traffic (`make demo-traffic` or `make demo-stack-traffic`) to generate diverse tenants/bots.

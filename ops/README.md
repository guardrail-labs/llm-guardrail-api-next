# Guardrail Observability & Ops

## Prometheus Scrape
See `ops/prometheus/scrape.yml.example`. Core endpoint:
- `/metrics` (enable via `METRICS_ROUTE_ENABLED`, optional `METRICS_API_KEY` via `X-API-KEY` or `Authorization: Bearer`)

## PromQL Starters

### Request rate (per tenant/bot)
```
sum by (tenant, bot) (rate(verifier_router_rank_total[5m]))
```

### Guardrail p95 latency
```
histogram_quantile(0.95, sum(rate(guardrail_latency_seconds_bucket[5m])) by (le, route))
```

### Decision breakdown (allow/block/clarify)
```
sum by (decision) (rate(guardrail_decision_total[5m]))
```

### Egress redactions rate
```
sum by (tenant, bot, kind) (rate(guardrail_egress_redactions_total[5m]))
```

### Verifier p95 by provider
```
histogram_quantile(0.95, sum(rate(guardrail_verifier_duration_seconds_bucket[5m])) by (le, provider))
```

### Circuit state (if exported)
```
max by (provider) (guardrail_verifier_circuit_state)
```

## Alerting Suggestions
- **High block spike**: increase in `rate(guardrail_decision_total{decision="block"}[5m])` above baseline.
- **Latency regression**: p95 latency above SLO for 10m.
- **Router rank rate drop to zero**: potential upstream outage.
- **Cardinality overflow**: if you see label=`overflow` in tenant/bot panels, consider sharding or filtering.

## Label Cardinality Guardrails
- Controlled by env:
  - `METRICS_LABEL_CARD_MAX` / `METRICS_LABEL_CARDINALITY_MAX` (default 1000)
  - `METRICS_LABEL_PAIR_CARDINALITY_MAX` (default matches above)
  - `METRICS_LABEL_OVERFLOW` (default "__overflow__")
- When capacity is exceeded, unseen tenant/bot values are reported as `overflow`.

## Grafana
Import `ops/dashboards/guardrail.json`. Panels include latency, decisions, redactions, router rank, and active tenants/bots.

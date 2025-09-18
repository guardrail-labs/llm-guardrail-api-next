# Guardrail API — PromQL Cookbook

> Grafana provisioning watches: `/repo/observability/grafana`
> Dashboard JSON lives at: `observability/grafana/guardrail-api.core.json`


## Redactions
- **Rate by rule (panel):**

```
increase(guardrail_egress_redactions_total[$__rate_interval]) by (rule_id)
```

- **Total redactions (window):**

```
sum(increase(guardrail_egress_redactions_total[15m]))
```

## Decisions counters
- **Total decisions by outcome:**

```
increase(guardrail_decisions_total[$__rate_interval]) by (outcome)
```

- **Redact decisions by rule:**

```
increase(guardrail_redact_decisions_total[$__rate_interval]) by (rule_id)
```

> To include tenant/bot labels, set `METRICS_DECISION_TENANT_BOT_LABELS=true`. Be mindful of cardinality.

## Rate Limiting
- **Rate-limited by tenant/bot:**

```
increase(guardrail_rate_limited_total{tenant="acme",bot="web"}[$__rate_interval])
```

- **Top offenders (last 1h):**

```
topk(10, sum(increase(guardrail_rate_limited_total[1h])) by (tenant,bot))
```

## Skips (bypasses)
- **Skip reasons (window):**

```
increase(guardrail_rate_limit_skipped_total[15m]) by (reason)
```

## Token health (live)
- **Current tokens for a bucket:**

```
guardrail_ratelimit_tokens{tenant="acme",bot="web"}
```

## Alert ideas (Grafana / Alertmanager)
- **Sustained throttling spike:**

```
sum(increase(guardrail_rate_limited_total[5m])) > 200
```

- **Sudden redaction surge per rule:**

```
max_over_time(sum by (rule_id) (increase(guardrail_egress_redactions_total[5m]))[30m:]) > 100
```

- **Unexpected bypass growth:**

```
sum(increase(guardrail_rate_limit_skipped_total[5m])) by (reason) > 50
```

> Tune thresholds to your traffic patterns. Prefer `increase()` over `rate()` for bursty, low-QPS services.

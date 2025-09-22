# SLOs and Alerting

This document outlines recommended service level objectives (SLOs) for Guardrail API and provides sample Alertmanager configurations.

## Core SLOs

| SLO | Target | Measurement |
| --- | --- | --- |
| Readiness availability | 99.9% | `guardrail_readyz_ok` over 5 minute windows |
| Webhook DLQ resolution | 99% resolved within 15m | `guardrail_webhook_dlq_depth` combined with replay timing |
| Decision latency | 95% < 250ms | Histogram `guardrail_decision_latency_seconds_bucket` |
| Block rate stability | < 50% sustained for 10m | Ratio of `guardrail_decisions_block_total` to `guardrail_decisions_total` |
| Autoconstraint audits | Alert on any spike | `guardrail_scope_autoconstraint_total` rate |

## Alertmanager examples

```yaml
route:
  receiver: oncall
  group_by: [service]
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 2h
  routes:
    - matchers:
        - severity = "page"
      receiver: pagerduty
    - matchers:
        - severity = "warn"
      receiver: slack

receivers:
  - name: pagerduty
    pagerduty_configs:
      - routing_key: <pagerduty-key>
  - name: slack
    slack_configs:
      - channel: '#guardrail-alerts'
        send_resolved: true
```

Pair the Alertmanager routing with the sample Prometheus rules in `deploy/prometheus/alerts/guardrail_slo.yml`.

## Example SLO burn alerts

- **Block-rate** – `sum(rate(guardrail_decisions_block_total[5m])) / sum(rate(guardrail_decisions_total[5m])) > 0.5`
- **DLQ backlog** – `rate(guardrail_webhook_dlq_depth[5m]) > 0 or max_over_time(guardrail_webhook_dlq_depth[10m]) > 0`
- **Readiness failures** – `min_over_time(guardrail_readyz_ok[5m]) < 1`
- **Autoconstraint spikes** – `sum by (result) (rate(guardrail_scope_autoconstraint_total[5m])) > 0`

Document alert descriptions and runbook links in Alertmanager annotations so on-call engineers can remediate quickly.

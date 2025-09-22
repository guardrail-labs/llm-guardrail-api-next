# Guardrail API — SLOs, Alerts, and Paging Policy

This doc proposes SLIs/SLOs and a paging policy you can adopt or tailor. The goal is
to page on **user-visible risk** and route everything else to async channels.

## SLIs (based on shipped metrics)

We intentionally use only metrics the API exposes today:

- `guardrail_readyz_ok` — 1 when the app is ready; 0 otherwise.
- `guardrail_readyz_redis_ok` — 1 when Redis is healthy/connected; 0 otherwise.
- `guardrail_webhook_dlq_depth` — number of webhook events sitting in the DLQ.

### Derived SLIs

- **App availability (per-pod):** `guardrail_readyz_ok`
- **Fleet availability (avg of pods):** `avg(guardrail_readyz_ok)`
- **Redis availability (avg):** `avg(guardrail_readyz_redis_ok)`
- **Webhook health (backlog):** `guardrail_webhook_dlq_depth`

> If/when we expose request counters/latency histograms, we can add error-rate & p95
> latency SLOs. For now the above are high-signal and actionable.

## SLOs (targets)

| SLO | Target | Window | Rationale |
| --- | ------ | ------ | --------- |
| Fleet availability | ≥ 99.9% | 30 days | Users can enforce policy reliably |
| Redis availability | ≥ 99.9% | 30 days | Core path relies on Redis |
| Webhook backlog | 0 sustained backlog | 30 min burn | Backlog implies missed/late automations |

**PromQL reference** (see rules files for exact expressions):

- Availability over 30d: `avg_over_time(avg(guardrail_readyz_ok)[30d])`
- Redis availability over 30d: `avg_over_time(avg(guardrail_readyz_redis_ok)[30d])`
- DLQ backlog sustained: `max_over_time(guardrail_webhook_dlq_depth[30m]) > 0`

## Paging Policy

- **Page (critical):**
  - Fleet availability drops (avg ready < 1.0) for ≥ 5m
  - Redis availability drops (avg redis_ok < 1.0) for ≥ 5m
  - DLQ backlog persists > 0 for ≥ 15m (indicates stuck webhook deliveries)

- **Warn (ticket / Slack):**
  - Brief readiness flaps (< 5m)
  - Small DLQ blips that clear < 15m

Use Alertmanager to route:
- `severity: critical` → PagerDuty (or your paging tool)
- `severity: warn` → Slack/Email

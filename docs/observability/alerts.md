# Guardrail Alerts (Trace Guard)

## Metrics
- guardrail_ingress_trace_invalid_traceparent_total{tenant,bot}
- guardrail_ingress_trace_request_id_generated_total{tenant,bot}

## Default alert thresholds
- Per-tenant/bot invalid traceparent > 0.10/s for 5m → Warning
- Global invalid traceparent > 1/s for 10m → Critical
- Per-tenant/bot generated RID > 0.50/s for 10m → Warning
- Global generated RID > 5/s for 15m → Info

Tune by baseline: inspect

```
sum by (tenant,bot)(rate(guardrail_ingress_trace_invalid_traceparent_total[1h]))
```

## Grafana quick panels
- *Stat*: Per-tenant invalid traceparent

```
sum by (tenant,bot)(rate(guardrail_ingress_trace_invalid_traceparent_total[5m]))
```

- *Stat*: Per-tenant RID generated

```
sum by (tenant,bot)(rate(guardrail_ingress_trace_request_id_generated_total[5m]))
```

## Runbook
1. **Triage scope**: Which tenant/bot? Global or localized?
2. **Check recent deploys**: client SDK, gateway, or proxy changes.
3. **Sample requests**: confirm malformed `traceparent` or missing RID.
4. **Advise clients**: fix propagation; ensure `X-Request-ID` policy is applied.
5. **Tune thresholds**: if noise, adjust per-tenant alert levels.

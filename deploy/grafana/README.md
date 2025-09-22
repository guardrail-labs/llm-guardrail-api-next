# Grafana dashboards

Import the dashboards in `dashboards/` via the Grafana UI or provisioning. Update datasource references to match your Prometheus datasource name.

## Recommended panels

1. **Autoconstraint by result (stacked)**

   ```promql
   sum by (result) (rate(guardrail_scope_autoconstraint_total[5m]))
   ```

2. **DLQ depth**

   ```promql
   max_over_time(guardrail_webhook_dlq_depth[15m])
   ```

Add runbook links in panel descriptions to accelerate on-call response.

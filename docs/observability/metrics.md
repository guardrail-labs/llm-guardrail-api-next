# Metrics reference

Guardrail API emits Prometheus metrics for critical subsystems. The table below calls out the key signals to monitor.

| Metric | Type | Description |
| --- | --- | --- |
| `guardrail_webhook_dlq_depth` | Gauge | Number of webhook events currently in the dead-letter queue. |
| `guardrail_readyz_ok` | Gauge | `1` when readiness checks pass. Use with `min_over_time` to detect outages. |
| `guardrail_decisions_override_total` | Counter | Count of decision overrides (label `status`). Spikes may indicate policy drift. |
| `guardrail_scope_autoconstraint_total` | Counter | Autoconstraint applications labeled by `result` (`constrained`, `explicit`). |
| `guardrail_decisions_block_total` | Counter | Total blocked decisions. Pair with `guardrail_decisions_total` for block rate. |

## Example PromQL

- **Readiness failing**

  ```promql
  min_over_time(guardrail_readyz_ok[5m]) < 1
  ```

- **DLQ backlog detected**

  ```promql
  max_over_time(guardrail_webhook_dlq_depth[10m]) > 0
  ```

- **Override spike**

  ```promql
  increase(guardrail_decisions_override_total[30m]) > 5
  ```

- **Autoconstraint activity by result**

  ```promql
  sum by (result) (rate(guardrail_scope_autoconstraint_total[5m]))
  ```

- **Block rate**

  ```promql
  sum(rate(guardrail_decisions_block_total[5m]))
  /
  sum(rate(guardrail_decisions_total[5m]))
  ```

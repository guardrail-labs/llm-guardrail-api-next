# Alert Runbook

## Redis Unhealthy

* **Alert**: `readyz_status{component="redis"} == 0` or `redis_connection_errors_total` increasing.
* **Actions**:
  1. `curl -fsS $SERVICE_URL/readyz` to confirm readiness failure context.
  2. Check Redis endpoint connectivity from the pod: `kubectl exec -it <pod> -- redis-cli -u $REDIS_URL PING`.
  3. Restart the workload if Redis recovered but readiness is still failing.

## DLQ Backlog

* **Alert**: `dlq_depth` above 10 for 5 minutes or `readyz_status{component="dlq"} == 1`.
* **Actions**:
  1. Inspect backlog: `curl -fsS $SERVICE_URL/admin/api/webhooks/dlq`.
  2. Replay stuck events: `curl -XPOST -fsS $SERVICE_URL/admin/api/webhooks/dlq/replay`.
  3. If replay fails, capture payloads and escalate to integrations team.

## Readiness Failing

* **Alert**: `/readyz` returning non-200 for >2 minutes.
* **Actions**:
  1. `curl -fsS $SERVICE_URL/readyz` to review component breakdown.
  2. Correlate with Grafana panels under `ops/grafana/*` for spikes or DLQ depth.
  3. Check recent deploys or policy pushes; roll back if the issue aligns with changes.

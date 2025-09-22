# Operations runbook

This runbook covers daily operational checks for Guardrail API and guidance for common incidents.

## Health vs readiness

- `GET /healthz` – Liveness probe. Returns `200` if the application process is responsive and its background workers have started. Does **not** verify Redis or policy load.
- `GET /readyz` – Readiness probe. Aggregates Redis connectivity, policy compilation, and background queue state. Returns JSON with per-component results such as `redis`, `policy`, and `dlq`.

Only route traffic to a pod after `/readyz` reports all checks as `true`.

## Dead-letter queue (DLQ)

Guardrail API uses Redis streams for webhook delivery. Failures are retried with exponential backoff and eventually moved to the DLQ when the max retry budget is exceeded.

- Metric: `guardrail_webhook_dlq_depth`
- Remediation: use `/admin/api/webhooks/dlq/retry` to requeue items after fixing the downstream system.
- Purge: `/admin/api/webhooks/dlq/purge` clears the DLQ. Run only after exporting the payloads for analysis.

## Circuit breaker

Webhook deliveries include a circuit breaker to protect downstream services. When the breaker is open, new deliveries are skipped and a metric spike appears in `guardrail_webhook_circuit_open_total`.

Reset the breaker after verifying downstream health with `/admin/api/webhooks/circuit/reset`.

## Common incidents

### Readiness failures

1. Check `/readyz` JSON for the failing component.
2. If Redis is down, restart the cache or failover.
3. If policy compilation fails, validate `rules.yaml` syntax and reload via `POST /admin/api/policies/reload`.

### DLQ backlog

1. Inspect DLQ depth metric and export failing events.
2. Fix the downstream integration and replay via `/admin/api/webhooks/dlq/retry`.
3. Monitor `guardrail_webhook_delivery_seconds` to confirm latency returns to normal.

### Autoconstraint spikes

1. Review `guardrail_scope_autoconstraint_total` for elevated activity.
2. Verify whether new tokens were provisioned with broad scopes.
3. Audit the security log for access anomalies.

### Elevated block rate

1. Check `guardrail_decisions_block_total` vs `guardrail_decisions_total`.
2. Review recent policy changes or upstream traffic for anomalies.
3. Use the admin UI to inspect overrides and adjudications.

### Ready but unresponsive UI

1. Confirm `/healthz` and `/readyz` still return `200`.
2. Check frontend logs for failed API calls (likely due to expired admin tokens).
3. Re-login or rotate admin tokens as needed.

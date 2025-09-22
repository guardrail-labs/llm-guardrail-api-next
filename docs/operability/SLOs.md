# Guardrail API SLOs

These are reference targets you can adopt or tune.

## Services in scope
- **Policy Enforcement API** (`/admin/api/decisions`, mitigation path)
- **Webhook Dispatch** (outbound deliveries)
- **Readiness** (Redis/file backends and workers)
- **DLQ** (webhook dead-letter queue)

## SLIs
- **Availability (enforcement)**  
  `enforcement_availability = 1 - rate(http_server_errors_total{job="guardrail",route="decisions"}[30d]) / rate(http_requests_total{job="guardrail",route="decisions"}[30d])`

- **Latency p95 (enforcement)**  
  `histogram_quantile(0.95, sum by (le)(rate(http_request_duration_seconds_bucket{job="guardrail",route="decisions"}[5m])))`

- **Webhook Delivery Success**  
  `delivery_success = 1 - (rate(guardrail_webhook_fail_total[30m]) / rate(guardrail_webhook_attempt_total[30m]))`

- **DLQ Health**  
  Backlog depth: `max_over_time(guardrail_webhook_dlq_depth[5m])`  
  Oldest age (if exported): `max_over_time(guardrail_webhook_dlq_oldest_seconds[5m])`

- **Readiness**
  `guardrail_readyz_ok == 1 AND guardrail_readyz_redis_ok == 1`

  See [Admin API readiness and version endpoints](../api/README.md#health-and-metadata-endpoints) for response details.

## Default SLO Targets (recommended)
- Availability (30d): **99.9%**
- Latency p95 (5m windows): **≤ 300 ms**
- Delivery Success (30m): **≥ 99.0%**
- DLQ Backlog: **= 0** sustained (warn on >0 for 5m, crit on >0 for 15m)
- Readiness: **= 1** (no gaps > 5m)

> Tune to your environment. These are conservative defaults for RC1.

## Paging Policy
- **Critical**: sustained SLO miss with user impact (availability, readiness, DLQ stuck, severe latency).
- **Warning**: early signals (transient DLQ, mild latency creep), notify on-call but don’t wake them at night.
- **Inhibit**: suppress warning when a critical for the same cause is firing.

## Runbooks
- **DLQ Backlog**: Check Admin DLQ UI → retry/purge → inspect circuit breaker & webhook endpoints → review 5xx rate at receivers.
- **Readiness**: Inspect `/readyz` metrics → Redis connectivity and consumer liveness → restart failing consumer.
- **Latency p95**: Check concurrency spikes, HPA scale, downstream provider latencies; consider reducing `limit` on list endpoints.
- **Availability**: Inspect 5xx counters → recent deploys → revert or feature-flag mitigation overrides.

See `docs/operability/runbooks/` for step-by-step flows.

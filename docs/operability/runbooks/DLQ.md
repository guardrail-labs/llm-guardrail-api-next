# Runbook: Webhook DLQ Backlog

## Symptoms
- Alerts: `GuardrailWebhookDLQBacklogWarn/Crit`
- Admin UI shows non-zero DLQ; deliveries stall.

## Steps
1. Confirm `guardrail_webhook_dlq_depth` vs `guardrail_webhook_attempt_total`.
2. Check circuit breaker state (open?).
3. Verify receiver 2xx rate and latency.
4. Retry from Admin UI; if repeated 4xx, coordinate with receiver owner.
5. Purge only if data is irrecoverable and approved (audit logs record action).
6. If consumer down, roll restart webhook worker Deployment/Helm release.

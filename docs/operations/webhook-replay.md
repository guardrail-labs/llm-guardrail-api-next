# Webhook DLQ Replay — Runbook

When a receiver is down or misconfigured, Guardrail routes failed deliveries to a DLQ. Once fixed, replay the DLQ to redeliver.

## Preconditions

- Receiver is healthy and verifying signatures.
- (Optional) Dry-run with **Send Test Event** first.

## Replay via Admin UI

1. Open **Admin → Webhooks**.
2. Click **Send Test Event** and confirm success in metrics/logs.
3. Enter a **Replay DLQ limit** (e.g., 100 or 1000) and click **Replay DLQ**.
4. Watch metrics:
   - `guardrail_webhook_events_total{event="replay_start"|"replay_done"}`
   - `guardrail_webhook_deliveries_total{outcome="sent"|"cb_open"|...}`
   - `guardrail_webhook_latency_seconds_*`

> Replays are **lock-synchronized** to prevent races.

## Replay via API

```bash
curl -X POST https://<host>/admin/webhook/replay \
  -H "Content-Type: application/json" \
  -H "Cookie: ADMIN_CSRF=<token>" \
  -d '{"limit": 500}'
```

- **CSRF:** Use the token issued by the admin UI (issue_csrf double-submit).
- **Limit:** Cap the batch to avoid thundering herds on partner systems.

## Safety Notes

- **Idempotency:** receivers should de-duplicate by event id or request_id.
- **Circuit breaker:** if the receiver fails during replay, the per-host circuit will open and short-circuit to DLQ with `outcome="cb_open"`; wait for cooldown, fix the receiver, then replay again.
- **Observability:** add Grafana panels for DLQ activity if desired; alert when failure ratio > 20% (already provided).

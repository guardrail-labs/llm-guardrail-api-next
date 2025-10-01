# Troubleshooting CI stuck tests

CI runs occasionally stall when an idempotent request wedges the middleware in
an `in_progress` state. Before restarting the pipeline, run through the [Idempotency
Ops](../ops/idempotency-ops.md) checklist:

1. List recent keys for the test tenant and identify the stuck key.
2. Inspect the key to confirm the fingerprint and expiry timestamp.
3. Purge the key if the leader is overdue or unhealthy.
4. Watch the idempotency metrics (`guardrail_idemp_*`) to confirm the purge
   cleared the lock and replays resume.

If the lock immediately reappears, notify the owning team—the backend is
likely retrying with a conflicting payload.

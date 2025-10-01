# Idempotency Ops

The idempotency middleware now exposes a set of admin-only endpoints and
metrics so operators can diagnose stuck replay queues without touching the
request path. All endpoints live under `/admin/idempotency` and require the
standard admin RBAC guard.

## Recent activity ring

Use `GET /admin/idempotency/recent?tenant=<name>` to retrieve the most recent
keys the middleware has seen. The endpoint accepts an optional `limit`
parameter (default 50, maximum 500) and returns each key with:

- `first_seen_at` and `last_seen_at` epoch timestamps.
- The current state (`in_progress`, `stored`, `released`, or `missing`).
- The most recent `replay_count` if the response is cached.

The handler updates the `guardrail_idemp_recent_size` gauge per tenant so you
can confirm the ring depth from Prometheus even without calling the API.

## Inspect a key

`GET /admin/idempotency/{key}?tenant=<name>` surfaces the full state snapshot
for a key without returning the cached body:

- Current state, expiry, and stored timestamp.
- Cached body size (bytes) and `content_type`.
- Replay count and fingerprint prefix (first 8 characters of the payload hash).
- Whether `touch_on_replay` is active for the deployment.

This is the fastest way to understand why a request is stuck (for example,
`state=in_progress` with an expiry timestamp in the past indicates the leader
never released the lock).

## Purging a key

`DELETE /admin/idempotency/{key}?tenant=<name>` removes the cached value, state,
and lock for a key. The response returns `{"purged": true}` when the key existed.
When a purge clears an expired `in_progress` lock the
`guardrail_idemp_stuck_locks_total` counter increments so you can alert on
manual clean-ups. Every purge increments `guardrail_idemp_purges_total` and
emits a structured log (`idemp_admin_purge`) with the masked key, tenant, and
replay count.

## Metrics quick-reference

The middleware now labels the primary counters with a `role` dimension so you
can separate leader and follower activity:

| Metric | Description |
| --- | --- |
| `guardrail_idemp_hits_total{role="follower"}` | Followers replaying cached responses. |
| `guardrail_idemp_misses_total{role="leader"|"follower"}` | Cache misses broken out by role. |
| `guardrail_idemp_in_progress_total{role="leader"}` | Leader executions in flight. |
| `guardrail_idemp_conflicts_total{role="follower"}` | Payload fingerprint conflicts detected by followers. |
| `guardrail_idemp_touches_total{role="follower"}` | TTL refreshes triggered by replays when `touch_on_replay` is enabled. |
| `guardrail_idemp_recent_size` | Size of the recent ring returned by `/recent`. |
| `guardrail_idemp_purges_total` | Count of admin purges per tenant. |
| `guardrail_idemp_stuck_locks_total` | Purges that removed expired `in_progress` locks. |

## Stuck lock playbook

1. **List recent keys**: `GET /admin/idempotency/recent?tenant=<name>` and
   locate the key stuck in `in_progress`.
2. **Inspect the key**: `GET /admin/idempotency/<key>?tenant=<name>` to confirm
   the expiry timestamp and fingerprint.
3. **Purge if safe**: `DELETE /admin/idempotency/<key>?tenant=<name>` to clear
   the value and lock.
4. **Monitor metrics**: Validate `guardrail_idemp_purges_total` and
   `guardrail_idemp_stuck_locks_total` increments, and ensure
   `guardrail_idemp_recent_size` drops back to normal.
5. **Watch logs**: Search for `idemp_leader_acquired`,
   `idemp_follower_wait_complete`, and `idemp_admin_purge` entries to verify
   the workflow. Keys are hash-masked by default unless `LOG_PII_OK=true`.

Following this flow keeps the cache healthy and provides the observability
needed to explain “stuck at 78%” style incidents to engineering teams.

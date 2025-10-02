# Idempotency Ops

Idempotency entries are cached per tenant and can be inspected safely through the
admin API without touching the request execution path. Use the tools below to
understand cache state, diagnose stalled requests, and evict bad entries.

## Listing recent keys

```
GET /admin/idempotency/recent?tenant=<tenant>&limit=50
```

* `tenant` is required. Unknown tenants return **404**.
* `limit` defaults to 50 and is capped at 500.
* The response is an array of `{key, first_seen_at, last_seen_at, state, replay_count}`
  sorted by most-recent activity.
* The `guardrail_idemp_recent_size` gauge is updated per tenant so dashboards
  can alert on unusually large rings.

Use this endpoint to identify which keys are executing (`state=in_progress`),
recently cached (`state=stored`), or have been evicted (`state=missing`).

## Inspecting a key

```
GET /admin/idempotency/{key}?tenant=<tenant>
```

Returns a structured snapshot without exposing the stored response body:

* `state` — `stored`, `in_progress`, `released`, or `missing`.
* `expires_at` — epoch seconds when the state/value will expire.
* `replay_count`, `stored_at`, `size_bytes`, `content_type`.
* `payload_fingerprint_prefix` — first 8 chars of the request fingerprint.
* `touch_on_replay` — current middleware configuration for TTL refresh.

Use this to verify TTLs are increasing on replays and to compare fingerprints
when debugging conflicts.

## Purging a key

```
DELETE /admin/idempotency/{key}?tenant=<tenant>
```

Deletes the cached value, state marker, and lock token. The response is
`{"purged": true|false}` indicating whether anything was removed.

When a lock is stuck in `in_progress` beyond its TTL the purge also increments
`guardrail_idemp_stuck_locks_total`. All purges increment
`guardrail_idemp_purges_total`, so alerts can track operational churn.

**Tip:** Always inspect the key first to confirm the fingerprint before
purging. After purge, followers will execute fresh requests.

## Metrics reference

* `guardrail_idemp_hits_total{role="follower"}` — successful replays.
* `guardrail_idemp_misses_total{role="leader"}` — new leaders entering the cache path.
* `guardrail_idemp_in_progress_total{role="leader"}` — active leader executions.
* `guardrail_idemp_conflicts_total{role="follower"}` — payload mismatches.
* `guardrail_idemp_recent_size{tenant}` — depth of the recent ring.
* `guardrail_idemp_purges_total{tenant}` — operator-triggered purges.
* `guardrail_idemp_stuck_locks_total{tenant}` — expired locks evicted via purge.
* `guardrail_idemp_touches_total{tenant}` — TTL refreshes on replay.

Watch these metrics alongside service latency to confirm that replays are
happening and that locks are not piling up.

## Stuck lock playbook

1. **List recent keys** and look for entries where `state=in_progress` but
   `expires_at` is in the past.
2. **Inspect the key** to verify the fingerprint and confirm the expiry.
3. **Purge the key** to clear the stale lock.
4. Monitor `guardrail_idemp_stuck_locks_total` and `guardrail_idemp_recent_size`
   to ensure the ring drains and new executions succeed.
5. If stuck locks continue, capture logs from `idempotency_event` (role
   "leader"/"follower") for the affected key to diagnose upstream failures.

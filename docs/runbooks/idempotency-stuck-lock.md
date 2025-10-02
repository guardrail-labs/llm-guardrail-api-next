# Runbook: Idempotency "Stuck Lock" Playbook

Audience: SRE / on-call (enterprise).  
Pre-reqs: RBAC token with admin scope for the tenant(s).

## When to use
Triggered by any of:
- `IdempotencyHighLockWaitP95`
- `IdempotencyHighLockWaitP99Global`
- SLO burns on `idemp:lock_wait_p95_seconds`
- Replay storm (`IdempotencyReplayStorm`)

## Environment
Set these before running commands (adjust per env):

```bash
export IDEM_BASE_URL="https://<env-domain>"   # e.g., https://api.stage.example.com
export IDEM_TENANT="<tenant-id>"              # optional; only if your gateway uses it
export IDEM_TOKEN="<bearer-jwt-or-pat>"
```

Headers:

- Authorization: `Bearer $IDEM_TOKEN`
- Optional: `X-Tenant: $IDEM_TENANT` if your gateway requires explicit tenant.

## 1) Snapshot recent idempotency activity

Lists the most recent keys so you can spot long-running locks or hot keys.

```bash
curl -fsSL "${IDEM_BASE_URL}/admin/idempotency/recent" \
  -H "Authorization: Bearer ${IDEM_TOKEN}" \
  -H "X-Tenant: ${IDEM_TENANT}" \
| jq -r '
  .items
  | sort_by(.updated_at // .stored_at // 0) | reverse
  | .[] | {
      key, tenant, state, replay_count,
      lock_expires_at, payload_fingerprint, stored_at, updated_at
    }'
```

If `.items` is not present, pipe the whole body to `jq` and inspect. Field names may vary
slightly across versions; prefer `state`, `lock*`, `stored_at`, `updated_at`, `replay_count`,
and `payload_fingerprint` if available.

### Identify likely stuck locks

Look for:

- `state == "in_progress"` with `lock_expires_at` in the past
- Same key appearing many times in a short window
- High `replay_count` with no recent `stored_at` change

## 2) Inspect a specific key

```bash
KEY="<paste-suspect-key>"
curl -fsSL "${IDEM_BASE_URL}/admin/idempotency/${KEY}" \
  -H "Authorization: Bearer ${IDEM_TOKEN}" \
  -H "X-Tenant: ${IDEM_TENANT}" \
| jq -r '
  {
    key, tenant, state, owner, payload_fingerprint,
    stored_at, updated_at, lock_expires_at, ttl_s, replay_count, headers
  }'
```

Signals to note:

- `state: "in_progress"` with past `lock_expires_at` → stale lock
- Repeated `owner` without progress → leader stuck
- `payload_fingerprint` mismatch vs recent traffic → conflicts

## 3) Safe remediation

### Option A — Non-destructive: wait for TTL to expire, watch metrics.

Use when impact is low and leader may recover.

Monitor `idemp:lock_wait_p95_seconds` and `idemp:hits_per_s`.

### Option B — Purge the key (break stale lock)

Use when `p95/p99` wait is elevated and key appears stuck.

```bash
curl -fsS -X DELETE "${IDEM_BASE_URL}/admin/idempotency/${KEY}" \
  -H "Authorization: Bearer ${IDEM_TOKEN}" \
  -H "X-Tenant: ${IDEM_TENANT}" \
  -w "\nstatus=%{http_code}\n"
```

After purging:

- The next follower will retry leader acquisition.
- Watch for a fresh `stored_at` and a drop in lock-wait metrics.

Caution: Only purge keys you verified are safe (low risk of duplicate side effects).
Idempotency protects repeats, but purging may allow one more execution.

## 4) Correlate with metrics (Grafana / PromQL)

Quick checks (adjust datasource in Grafana Explore):

- `idemp:lock_wait_p95_seconds`
- `idemp:lock_wait_p99_seconds`
- `topk(10, idemp:conflict_rate_per_s)`
- `idemp:replay_count_p95`
- `idemp:error_rate_per_s`

## 5) Closure

- Confirm alerts auto-resolved and `p95/p99` wait normalizes.
- Add an incident note with the key(s) purged and time window.
- If conflicts were the cause, file a ticket to the client team to stabilize keys.

## Appendix: Helper script

We include a tiny helper at `tools/idempotency/idem-admin.sh` with `recent|get|purge`.

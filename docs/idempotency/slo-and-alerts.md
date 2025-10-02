# Idempotency SLOs & Alerts

## SLOs (prod defaults)

- **Lock wait p95 ≤ 3s** in enforce mode (proxy for stuck-lock avoidance).
- **Hit ratio ≥ 0.60** (followers hit cache vs leaders doing fresh work).
- **Conflict rate ≤ 1%** of enforce-mode traffic.

Tune per-tenant as needed by overriding alert label matchers.

## Key alerts
- `IdempotencyHighLockWaitP95` / `IdempotencyHighLockWaitP99Global`
- `IdempotencyLowHitRatio`
- `IdempotencyConflictSpike`
- `IdempotencyBackendErrorSpike`
- `IdempotencyReplayStorm`
- `SLOLockWaitP95FastBurn` / `SLOLockWaitP95SlowBurn`

## Interpreting metrics
- `IDEMP_LOCK_WAIT_*` – follower wait durations; high p95/p99 suggests contention or
  leader stalls.
- `IDEMP_HITS` vs `IDEMP_MISSES` – rough cache-effectiveness proxy.
- `IDEMP_CONFLICTS` – payload mismatches for same key (unstable keys).
- `IDEMP_ERRORS` – backend phases: `get|put|acquire|release|meta|touch|bump_replay`.
- `IDEMP_REPLAY_COUNT_HIST` – how often responses are reused.

See the runbook for stuck locks (separate doc) to use `/admin/idempotency/*`.

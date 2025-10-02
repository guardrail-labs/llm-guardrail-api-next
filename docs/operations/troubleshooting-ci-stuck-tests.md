# Troubleshooting CI Stuck Tests

End-to-end tests occasionally pause while waiting for idempotent requests to
finish. The admin idempotency tooling provides a safe way to inspect and clear
entries without restarting the suite.

1. Use the [Idempotency Ops guide](./idempotency-ops.md) to list recent keys for
   the tenant under test.
2. Inspect the key to verify the payload fingerprint and TTLs.
3. Purge the stuck entry if it is past its expiration. This will unblock the
   follower request and allow CI to continue.
4. Watch `guardrail_idemp_stuck_locks_total` and the CI logs for the
   corresponding `idempotency_event` entries to understand why the leader failed.

If stuck locks recur, capture the fingerprints and request payloads involved in
CI so engineering can reproduce the failure locally.

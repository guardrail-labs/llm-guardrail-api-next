# Idempotency rollout guide

The idempotency middleware supports three rollout modes that can be tuned per environment.
Defaults are intentionally conservative so that new deployments start in a safe
"shadow" configuration and can graduate to full enforcement over time.

## Environment defaults

| Environment | Default mode | Lock TTL (s) | Strict fail closed | Rationale |
| ----------- | ------------ | ------------ | ------------------ | --------- |
| `dev`       | `observe`    | 30           | `false`            | Shadow-only with short TTL for rapid iteration. |
| `stage`     | `observe`    | ≥60          | `false`            | Mirrors prod timing without blocking. |
| `prod`      | `enforce`    | ≥120         | `false`            | Enforces dedupe once shadow telemetry is healthy. |
| `test`      | Inherited     | 60           | `false`            | Matches explicit overrides for deterministic runs. |

Environment variables can override any of the above defaults using
`IDEMPOTENCY_*` keys. For example setting `IDEMPOTENCY_MODE=observe` on production will
leave enforcement disabled while still emitting metrics.

## Override knobs

| Setting | Description |
| ------- | ----------- |
| `IDEMPOTENCY_MODE` | `off`, `observe`, or `enforce`. `observe` records metrics without
blocking. |
| `IDEMPOTENCY_ENFORCE_METHODS` | Comma-separated HTTP verbs that require idempotency. |
| `IDEMPOTENCY_EXCLUDE_PATHS` | Comma-separated list of path globs (supports `*`) that bypass
enforcement even when the mode is `enforce`. |
| `IDEMPOTENCY_LOCK_TTL_S` | Upper bound on lock lifetime. Dev/stage clamp this to safe
ranges; prod enforces a minimum of 120 seconds. |
| `IDEMPOTENCY_WAIT_BUDGET_MS` / `IDEMPOTENCY_JITTER_MS` | Controls follower wait window
and polling jitter when deduping. |
| `IDEMPOTENCY_STRICT_FAIL_CLOSED` | When true, treat backend failures as 5xx instead of
failing open. Defaults to false in all environments. |

## Enforcing specific routes

To enforce idempotency on a new route:

1. Enable the middleware by keeping `IDEMPOTENCY_MODE=observe` (or `enforce`) in the target
environment.
2. Ensure the route's HTTP verb appears in `IDEMPOTENCY_ENFORCE_METHODS`.
3. Remove the route from `IDEMPOTENCY_EXCLUDE_PATHS` (globs are matched using `fnmatch`).
4. Monitor `guardrail_idemp_*` metrics filtered by `mode` to confirm replay/lock behaviour.
5. Flip `IDEMPOTENCY_MODE=enforce` once shadow metrics look healthy.

## Suggested rollout sequence

1. **Shadow** – start with `IDEMPOTENCY_MODE=observe` everywhere. Verify the exclude list
covers health probes and admin routes.
2. **Per-route trials** – temporarily remove a route from `IDEMPOTENCY_EXCLUDE_PATHS` while
keeping the global mode in `observe` to measure would-be enforcement metrics without risk.
3. **Stage enforcement** – set `IDEMPOTENCY_MODE=enforce` in staging after a successful
shadow bake. Review lock wait histograms to ensure latency budgets are respected.
4. **Production ramp** – flip production to `enforce`, optionally in combination with
a narrowed `IDEMPOTENCY_ENFORCE_METHODS` set. Re-enable excluded routes incrementally as
confidence grows.
5. **Strict fail-closed (optional)** – once the backing store is highly available, opt into
`IDEMPOTENCY_STRICT_FAIL_CLOSED=true` for critical transaction paths.

Document each change alongside release notes to maintain clear audit history of rollout
state per environment.

# Idempotency layer

**What it does**
- Accepts `X-Idempotency-Key` (1–200 chars, `[A-Za-z0-9_-]`).
- The first run **executes** and (if cacheable) stores a response.
- Replays return the stored response and set `Idempotency-Replayed: true`.
- Same key + different body → treated as a **fresh run** after the current in-flight run finishes; the new run overwrites the previous cache.

**Not stored**
- HTTP 5xx responses
- Streaming responses (unless `cache_streaming=true`)
- Bodies larger than `IDEMP_MAX_BODY_BYTES` (default **256 KiB**)

**Config (env)**
- `IDEMP_METHODS` (default `POST`) — comma-separated list, e.g. `POST,PUT`
- `IDEMP_TTL_SECONDS` (default `120`)
- `IDEMP_MAX_BODY_BYTES` (default `262144`)

**Concurrency**
- Single-flight via a **lock owner token**; only the owner can release.
- Followers use **exponential backoff with jitter** and stop waiting as soon as:
  - a cached value exists, or
  - the lock disappears / state is not `in_progress`.

**Admin metadata**
- `state`, `lock`, `owner`, `payload_fingerprint`, `stored_at`, `replay_count`, `ttl_remaining`.
- `recent` lists the latest keys by time.

**Prometheus**
- `guardrail_idemp_backoff_steps_total` — increments when followers back off.
- (Existing) hits/misses/conflicts/in_progress/replays/lock_wait seconds.

**Examples**
```bash
curl -s -X POST localhost:8000/v1/guardrail \
  -H 'X-Idempotency-Key: abc123' -H 'Content-Type: application/json' \
  -d '{"prompt":"ping"}' -i
```

---

## Notes

- This bundle **doesn’t** change any public API routes; it enriches store `meta()` and hardens concurrency semantics.
- We kept the **default method** scope to `POST`, with opt-in `PUT`/`PATCH` via env.
- The Redis lock now stores JSON `{"owner": <uuid>, "payload_fingerprint": <sha256>}` so we can safely compare and release by owner. Memory store mirrors this behavior for tests.

---

If you want, I can also add an admin route test asserting `ttl_remaining`/`stored_at` presence; the store already provides it.

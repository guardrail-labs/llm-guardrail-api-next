# Admin session security

The Admin UI automatically provisions a short-lived session when you first
access any `/admin` route. Two cookies are issued:

- `admin_sess` – an HttpOnly session marker used purely for CSRF rotation.
- `admin_csrf` – the double-submit CSRF token surfaced to the browser.

Both cookies are bound to the `/admin` path, marked `SameSite=Strict`, and
inherit the default TTL of 20 minutes (`ADMIN_SESSION_TTL_SECONDS`, defaults to
`1200`). When the session cookie is missing or expires, a new pair is minted and
the CSRF token is rotated alongside it.

For production, the middleware sets strict attributes on every session: the
session cookie is `Secure`, `HttpOnly`, and `SameSite=Strict`, while the CSRF
cookie is `Secure`, `SameSite=Strict`, and readable by client-side JavaScript.
Both share the same TTL. Local HTTP development flows can opt out of the `Secure`
flag by setting `ADMIN_COOKIE_INSECURE=1`; all other attributes remain
unchanged. Cookie names and the admin path are also configurable via
`ADMIN_SESSION_COOKIE`, `ADMIN_CSRF_COOKIE`, and `ADMIN_COOKIE_PATH`.

## Adjudication logs API

Operators can review recent guardrail adjudications via two admin-only
endpoints:

- `GET /admin/adjudications` – returns the newest records in JSON.
- `GET /admin/adjudications.ndjson` – streams the same records as
  newline-delimited JSON for ingestion pipelines.

Each record is PII-safe and includes the timestamp, tenant, bot, request ID,
decision, provider, rule hits, latency, sampling flag, and a SHA256 hash of the
prompt (the raw prompt text is never stored). Filters for `tenant`, `bot`,
`decision`, `mitigation_forced`, `from_ts`, `to_ts`, and sort order mirror the
query parameters on both endpoints. Pagination is supported on the JSON route
with `limit` (default 50, maximum 500) and `offset`.

The in-memory recorder retains the most recent events in a ring buffer. Adjust
`ADJUDICATION_LOG_CAP` to raise or lower the maximum number of stored records
before older entries are evicted.

# Admin session security

The Admin UI automatically provisions a short-lived session when you first
access any `/admin` route. Two cookies are issued:

- `admin_sess` – an HttpOnly session marker used purely for CSRF rotation.
- `admin_csrf` – the double-submit CSRF token surfaced to the browser.

Both cookies are bound to the `/admin` path, marked `SameSite=Strict`, and
inherit the default TTL of 30 minutes (`ADMIN_SESSION_TTL_SECONDS`). When the
session cookie is missing or expires, a new pair is minted and the CSRF token is
rotated alongside it.

For production, cookies are sent with the `Secure` attribute by default. Local
workflows that rely on HTTP can opt out by setting `ADMIN_SECURE_COOKIES=0`; all
other attributes remain unchanged. Cookie names and the admin path are also
configurable via `ADMIN_SESSION_COOKIE`, `ADMIN_CSRF_COOKIE`, and
`ADMIN_COOKIE_PATH`.

## Adjudication logs API

Operators can review recent guardrail adjudications via two admin-only
endpoints:

- `GET /admin/adjudications` – returns the newest records in JSON.
- `GET /admin/adjudications/export.ndjson` – streams the same records as
  newline-delimited JSON for ingestion pipelines.

Each record is PII-safe and includes the timestamp, tenant, bot, request ID,
decision, provider, rule hits, latency, sampling flag, and a SHA256 hash of the
prompt (the raw prompt text is never stored). Filters for `start`, `end`,
`tenant`, `bot`, `provider`, `request_id`, and `limit` mirror the query
parameters on both endpoints. Results default to 100 items and are capped at
1,000 per request.

The in-memory recorder retains the most recent events in a ring buffer. Adjust
`ADJUDICATION_LOG_CAP` to raise or lower the maximum number of stored records
before older entries are evicted.

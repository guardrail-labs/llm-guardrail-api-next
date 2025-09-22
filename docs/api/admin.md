# Admin API reference

The admin surface is intended for operational workflows that require elevated privileges. All endpoints below require an admin token with CSRF protections enforced for browser-originated requests.

## Decisions API

- `GET /admin/api/decisions` – Cursor-paginated list ordered by decision time. Supports filters: `tenant`, `bot`, `status`, `policy`, `from`, `to`, `cursor`, and `limit` (max 500).
- `GET /admin/api/decisions/{decision_id}` – Fetch a single decision, including adjudications and override annotations.
- `POST /admin/api/decisions/{decision_id}/override` – Apply an override with body `{ "status": "allow" | "block", "reason": "..." }`.

### Cursor parameters

List responses include a `next_cursor` token. Clients should treat the cursor as opaque and pass it back using the `cursor` query parameter. Cursors encapsulate the last seen decision id and timestamp, enabling consistent pagination without duplication.

## Adjudications API

- `GET /admin/api/adjudications` – Cursor-paginated list with filters `tenant`, `bot`, `status`, `actor`, and `from`/`to` ranges.
- `POST /admin/api/adjudications` – Create an adjudication linked to a decision. Requires a JSON body with `decision_id`, `status`, and optional `notes`.
- `PATCH /admin/api/adjudications/{adjudication_id}` – Update notes or status.

## Export endpoints

- `GET /admin/api/decisions/export` – Streams NDJSON for decisions. Supports the same filters as the list API and requires that the request resolve to a single scope when autoconstraint is enabled.
- `GET /admin/api/adjudications/export` – NDJSON export for adjudications with identical scoping rules.

Exports use long-lived connections; clients should set generous timeouts and stream to disk. Responses include `X-Export-Approx-Count` when a precomputed estimate is available.

## CSRF considerations

Browser-based clients must include the `X-CSRF-Token` header for unsafe methods. The admin UI issues the token via a `Set-Cookie` header on login. Non-browser automation should avoid cookies entirely and use bearer tokens over HTTPS.

The override endpoint (`/override`) is intentionally safe for demonstration environments and can be enabled with the `ADMIN_ENABLE_GOLDEN_ONE_CLICK` flag. Production deployments should disable the demo flag and require explicit overrides from authenticated operators.

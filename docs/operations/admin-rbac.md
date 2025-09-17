# Admin RBAC (Scaffold)

This scaffold gates **admin POST** endpoints behind a shared admin key when enabled.

## Config

```yaml
admin_rbac_enabled: true
admin_api_key: "replace-me"
```

When enabled, POST endpoints (e.g., `/admin/api/policy/reload`, `/admin/webhook/replay`) require:

- Header: `X-Admin-Key: <admin_api_key>` **or**
- Cookie: `admin_key=<admin_api_key>`

GET endpoints remain open for inspection/observability.

CSRF double-submit (cookie `ui_csrf` + body/header token) still applies.

This is a minimal first step. Future RBAC can add users/roles (viewer/operator/admin) and proper sessions.

## Example (curl)

```bash
TOKEN="testtoken123"
curl -X POST https://<host>/admin/api/policy/reload \
  -H "X-Admin-Key: REPLACE_ME" \
  -H "Content-Type: application/json" \
  --cookie "ui_csrf=${TOKEN}" \
  -d "{\"csrf_token\":\"${TOKEN}\"}"
```

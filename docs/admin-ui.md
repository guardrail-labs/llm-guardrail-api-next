# Admin UI (minimal)

Read-only surface for inspecting and reloading guardrail policy.  The UI only
exposes status pages and a policy reload action; there are no mutation paths
other than the reload call.

## Environment variables

Authentication uses either a bearer token or basic auth:

- `ADMIN_UI_TOKEN` – preferred bearer secret
- `ADMIN_UI_USER` / `ADMIN_UI_PASS` – basic auth fallback if token unset
- `ADMIN_UI_SECRET` – optional HMAC secret for CSRF (falls back to
  `APP_SECRET` / `SECRET_KEY`)
- `GRAFANA_URL` – optional link to external dashboards

## Quickstart

```bash
export ADMIN_UI_TOKEN=devtoken
uvicorn app.main:create_app --factory
# then open http://localhost:8000/admin/ui
```

## Security notes

- Deploy behind TLS; set `Secure` cookies via reverse proxy.
- Rotate the token or credentials periodically.
- The reload action uses double-submit CSRF tokens derived from `ADMIN_UI_SECRET`.


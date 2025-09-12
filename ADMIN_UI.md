# Admin / Demo UI

Endpoints (mounted under `/admin`):

- `GET /admin` – landing
- `GET /admin/bindings` – list + validation badges
- `POST /admin/bindings/apply` – accepts JSON; dry-run unless `ADMIN_ENABLE_APPLY=1`
- `GET /admin/active-policy?tenant=&bot=` – selected binding and candidates
- `GET /admin/metrics` – redirect to `/metrics`

Enable apply:

```
export ADMIN_ENABLE_APPLY=1
```

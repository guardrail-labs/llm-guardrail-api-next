# Configuration Matrix

| Variable | Values | Effect |
| --- | --- | --- |
| `ADMIN_AUTH_MODE` | `disabled` \| `cookie` \| `oidc` | Selects admin authentication scheme. `disabled` exposes UI locally only; `oidc` requires OIDC issuer/audience. |
| `AUDIT_BACKEND` | `memory` \| `file` \| `redis` | Overrides audit persistence backend. When unset, falls back to `AUDIT_LOG_FILE` for file mode or in-memory. |
| `AUDIT_LOG_FILE` | Path | Enables append-only NDJSON audit log on disk when set. |
| `MITIGATION_STORE_BACKEND` | `memory` \| `file` \| `redis` | Forces mitigation persistence backend. |
| `MITIGATION_STORE_FILE` | Path | Enables file-backed mitigation store when present. |
| `REDIS_URL` | redis://... | Enables Redis-backed rate limit, mitigation store, and DLQ persistence. |
| `ADMIN_ENABLE_GOLDEN_ONE_CLICK` | `0/1`, `true/false` | Allows admins to trigger pre-approved golden mitigations. |
| `FORCE_BLOCK` | `0/1`, `true/false` | Forces block verdicts for all tenants unless exempted. |
| `FORCE_BLOCK_TENANTS` | Comma list | Targets `FORCE_BLOCK` to specific tenants only. |

## Security Notes

* Secrets are never logged by default; redaction middleware strips sensitive fields from audit trails.
* NDJSON exports are filtered to include only tenant-visible fields.

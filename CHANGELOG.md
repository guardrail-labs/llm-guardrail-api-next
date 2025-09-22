# Changelog

## Unreleased
### Added
- Feature flag to auto-constrain service token scope and emit effective scope headers when enabled.

### Fixed
- Normalize export scopes to single values, returning `400` when ambiguous multi-tenant tokens omit filters.

## v0.1.0-rc1 (2025-09-07)
### Added
- Admin audit persistence (file/redis) + NDJSON export.
- Health (`/healthz`) & readiness (`/readyz`) with Redis/file checks.
- Override metrics tiles; gauges: `guardrail_readyz_ok`, `guardrail_readyz_redis_ok`, `guardrail_webhook_dlq_depth`.
- Version endpoint `/version` with build metadata.

### Changed
- Webhook backoff + jitter; circuit-breaker guard on open state.
- Cursor pagination for decisions/adjudications; filters parity.
- Mitigation mode persistence (file/redis) with delimiter-safe keys.

### Fixed
- Redis readiness accuracy and all-consumer enforcement.
- DLQ depth metric freshness (updated on enqueue/purge/retry).
- Admin UI CSRF placement for Apply Golden.

### Security
- Security (P0): Fix RBAC bypass where omitted tenant/bot filters were treated as in-scope for scoped service tokens. Admin and export endpoints now require explicit filters unless the token scope is "*".

### Upgrade notes
- If using Redis backends, ensure `REDIS_URL` reachable; `/readyz` will fail otherwise.
- For file backends, create writable dirs for `AUDIT_LOG_FILE` and `MITIGATION_STORE_FILE`.

# Changelog

## Unreleased
### Added
- Feature flag to auto-constrain service token scope and emit effective scope headers when enabled.
- Observability for scope autoconstraint, including Prometheus counter labels, admin UI "Effective scope" chip, and optional audit log entries.
- OpenAPI metadata polish with canonical tags, summaries, and response examples for admin APIs.
- Lightweight SDKs for Python (`guardrail_api`) and TypeScript (`@guardrail/api`) with quickstart docs.
- Postman collection and language-specific quickstarts for curl, Python, and TypeScript.
- SDK publish workflow to build packages on release tags and publish when registry credentials are configured.

### Fixed
- Normalize export scopes to single values, returning `400` when ambiguous multi-tenant tokens omit filters.

## [1.0.0-rc1] — 2025-09-21
### Added
- Autoconstraint observability: Prom counter + UI chip (flagged feature).
- Admin/docs set: security/scoping, admin API, ops runbook, helm, metrics, SLOs.
- RC artifacts are now supply-chain hardened:
  - Container image is **cosign keyless signed** (OIDC).
  - **Build provenance attestation** published to GHCR.
  - **SBOM (SPDX JSON)** attached to the GitHub Release.

### Changed
- List endpoints support multi-scope union when autoconstraint is ON.

### Security
- RBAC P0: scoped tokens no longer bypass when tenant/bot omitted.

## v0.1.0-rc1 (2025-09-07)
### Added
- Admin audit persistence (file/redis) + NDJSON export.
- Health (`/healthz`) & readiness (`/readyz`) with Redis/file checks.
- Override metrics tiles; gauges: `guardrail_readyz_ok`, `guardrail_readyz_redis_ok`, `guardrail_webhook_dlq_depth`.
- Version endpoint `/version` with build metadata.

### Changed
- Webhook backoff + jitter; circuit-breaker guard on open state.
- Cursor pagination for decisions/adjudications; filters parity.
- Autoconstraint list endpoints honor multi-tenant/bot scopes by applying `IN (...)` filters when callers omit explicit filters.
- Mitigation mode persistence (file/redis) with delimiter-safe keys.

### Fixed
- Redis readiness accuracy and all-consumer enforcement.
- DLQ depth metric freshness (updated on enqueue/purge/retry).
- Admin UI CSRF placement for Apply Golden.
- Removed duplicate tenant/bot keyword arguments when invoking list providers.

### Security
- Security (P0): Fix RBAC bypass where omitted tenant/bot filters were treated as in-scope for scoped service tokens. Admin and export endpoints now require explicit filters unless the token scope is "*".

### Upgrade notes
- If using Redis backends, ensure `REDIS_URL` reachable; `/readyz` will fail otherwise.
- For file backends, create writable dirs for `AUDIT_LOG_FILE` and `MITIGATION_STORE_FILE`.

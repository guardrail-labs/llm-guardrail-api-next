# Changelog

## [v1.0.0-rc1] - 2025-09-23
### Added
- Security model doc: clarified **enforcement posture** — disallowed outputs are intercepted
  and mitigated (block/clarify/redact) before returning to clients when policies are active.
  Administrators must enable/maintain appropriate packs for compliance.
- Perf docs: smoke + compare flow; CI artifacts guidance.
- Terraform HA example notes (real chart path; override fallback).
- Repo audits doc (gitleaks/trufflehog/pinning).
- Enterprise tests doc (opt-in; runner/image expectations).

### Fixed
- Webhook metrics/CB handling made robust in CI paths; formatting for ruff.
- Bandit B101 cleanup: explicit 4xx on invalid inputs (admin routes).
- Mypy: typed helpers instead of ambiguous lambdas.

### CI
- Action pinning audit: artifact token/perms fixed; JSON/MD outputs uploaded reliably.
- Repo audit: gitleaks/trufflehog report preservation on non-zero exits.

[v1.0.0-rc1]: https://github.com/<org>/<repo>/releases/tag/v1.0.0-rc1

## [1.0.0-rc3] — 2025-10-10
### Added
- PR-012: Release gating automation, VERSION source of truth, upgrade notes, and CI.

### Notes
- RC3 recap aligning automation with GA readiness.

## [1.0.0] — 2025-10-20
### Added
- PR-006: Policy packs v1 (HIPAA/GDPR/California) + loader + evaluator.
- PR-007: Bench harness, SLOs, clarify-rate tuner.
- PR-008: Grafana dashboards & alerts with runbook.
- PR-009: Per-tenant audit export API/CLI with redaction and admin guard.
- PR-010: Decision-header contract tests (allow/clarify/block).
- PR-011: Jailbreak corpus + offline eval harness.

### Changed
- PR-002/002a/003: Unicode normalize + zero-width/RTL guard; confusables detection
  with policy toggles and metrics; middleware wiring.

### Fixed
- PR-001: Idempotency key masking (no full key, even short).
- PR-004a: Streamed multipart reads enforcing max_bytes without OOM.
- PR-005a: Verifier health cache keyed by object identity.

### Notes
- Default behavior remains **advisory** for sanitizer/policy packs; enforcement
  via decision engine based on headers.

[1.0.0-rc3]: https://github.com/<org>/<repo>/releases/tag/v1.0.0-rc3
[1.0.0]: https://github.com/<org>/<repo>/releases/tag/v1.0.0

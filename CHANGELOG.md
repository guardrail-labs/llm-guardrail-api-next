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

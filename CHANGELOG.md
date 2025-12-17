# Changelog

## [1.6.1](https://github.com/guardrail-labs/llm-guardrail-api-next/compare/v1.6.0...v1.6.1) (2025-12-17)


### Documentation

* fix case-collision; rename Quickstart.md to STACK_QUICKSTART.md ([accb093](https://github.com/guardrail-labs/llm-guardrail-api-next/commit/accb0937f40811107f752b326a76d71f54e0f6f1))

## [1.6.0](https://github.com/guardrail-labs/llm-guardrail-api-next/compare/v1.5.0...v1.6.0) (2025-11-25)


### Features

* expose billing and admin usage metrics in core ([41896c6](https://github.com/guardrail-labs/llm-guardrail-api-next/commit/41896c6626bc528dee1907f46716e5be23705d1f))

## [1.5.0](https://github.com/WesMilam/llm-guardrail-api-next/compare/v1.4.0...v1.5.0) (2025-11-11)


### Features

* **observability:** enforce tenant scope guard and tests ([d94778c](https://github.com/WesMilam/llm-guardrail-api-next/commit/d94778cb226488f60b2a8450a2b712f3f933da82))


### Documentation

* refresh README + SECURITY for v1.4.0 (Guardrail Labs, LLC — patent pending) ([edb31b2](https://github.com/WesMilam/llm-guardrail-api-next/commit/edb31b274cecb2de3f150da42cdf58a7bf4076b2))

## [Unreleased]
### Added
- Added Redis-backed DLQ for webhooks (schedule, replay, quarantine)
- Added admin endpoints for pending/quarantine/replay/delete
- Added route-level tests with service mocking (no Redis in CI)
- feat(stream): SSE header hygiene middleware (proxy-safe, gzip avoided)
- feat(stream): EventStream helper (frames, retry, heartbeat)
- feat(stream): RedactorBoundaryWriter to prevent mid-chunk secret leaks
- test(stream): headers, boundaries, generator behavior
- feat(retention): per-tenant TTL policies (Redis store)
- feat(retention): purge coordinator + signed receipts (HMAC by default; Ed25519 optional)
- feat(admin): retention policy & purge admin API with CSRF enforcement
- ops: optional periodic purge worker + Prom metrics
- test: receipts/signatures, coordinator, admin API

### Fixed
- fix(middleware): correct middleware registration order (Unicode ingress first; SSE vs
  compression)

### Changed
- perf(redis): atomic token-bucket via Lua (1 RTT)
- perf(redis): idempotency SET NX PX + pipeline touch
- perf(http): shared AsyncClient with tuned pool/keepalive
- perf(app): lifespan warm-up (Lua scripts, compliance registry)
- metrics: request latency histogram and middleware

## 1.0.0 — GA (2025-11-02)
- Core LLM firewall stabilized (ingress/egress sanitizers, rate-limit, idempotency).
- OpenAPI schema frozen and committed.
- Production Docker image build workflow with SHA256 digests.
- Compatible with Enterprise 1.0.0 and Verifier 1.0.0.

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

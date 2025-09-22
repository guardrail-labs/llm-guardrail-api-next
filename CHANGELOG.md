# Changelog

## v1.0.0-rc1 — Release Candidate
**Highlights**
- Core policy enforcement & overrides, secure Admin UI (CSRF/cookies), OIDC + scoped service tokens.
- Cursor APIs for Decisions/Adjudications with stable ordering; exports & audited deletes.
- Webhooks with backoff/jitter, DLQ + metrics/alerts.
- Observability: /healthz, /readyz, Prometheus gauges & example rules, Grafana dashboard.
- Helm deploy path, GitHub Actions release, SBOM attached.

**Notable fixes since last snapshot**
- Scope bypass resolved; multi-scope autoconstrain handled across decisions/adjudications.
- SDK export endpoints corrected; RC workflow permissions; SBOM filename alignment.
- Docker build robustness (pip retries/cache); perf tool (`bench.py`) ruff/mypy clean.

**Docs & Ops**
- SLOs & paging policy docs; Prometheus alert rules tuned (continuous backlog).
- Terraform HA example (Redis + 2 replicas), CI terraform fmt check.

> RC phase = feature freeze. Only bug fixes & docs polish land until GA.

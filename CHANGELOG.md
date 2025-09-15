# Changelog

## [Unreleased]
### Added
- Joint tenant/bot metrics label guard via `METRICS_LABEL_PAIR_CARDINALITY_MAX`.
- Conditional fallback for `/admin/bindings*` when persistent admin routes are missing.
- Restored `policy_admin` routes such as `/policy/version`.

## [0.1.0] — 2025-09-07
### Added
- Directional observability (ingress/egress families, tenant/bot breakdowns)
- OCR v1 for images/PDFs → text pipeline
- Admin config endpoints and binding store (per-tenant/bot policy packs)
- One-command packaging with Prometheus & Grafana
- Docs: Quickstart, Operator Guide, OpenAI Integration, Demo Script
- Sales polish: README, License, Playbooks

### Notes
- Roadmap: verifier specialization, adjudication logs, auto-mitigation toggles, admin UI

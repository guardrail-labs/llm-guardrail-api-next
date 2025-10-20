# Upgrade to v1.0.0

## Breaking-ish (headers now guaranteed)
- `X-Guardrail-Decision`: `allow|block-input` (always set by verifier path).
- `X-Guardrail-Mode`: `allow|clarify|block_input` (sanitizer/verifier).
- `X-Guardrail-Incident-ID`: present when default-blocking on verifier outage.

## New config/toggles (defaults shown)
- Sanitizer (confusables)
  - `confusables_action`: `flag` (others: `off|escape|clarify|block`)
  - `max_confusables_ratio`: `0.05`
- Multimodal gate
  - `enabled`: `true`
  - `max_bytes`: `5 MiB`
  - `action`: `flag`
- Policy packs
  - Packs load from `policy/packs/*.yaml`.
  - Tenant overrides via `apply_overrides()` in `app/policy/packs.py`.

## Ops
- Prometheus:
  - `guardrail_sanitizer_events_total{type}`
  - `guardrail_sanitizer_actions_total{action}`
  - `guardrail_verifier_events_total{event}`
- Grafana dashboards under `ops/grafana`.

## Recommended rollout
1. **Stage**: enable Unicode & confusables (`flag`), multimodal gate (`flag`).
2. **Observe**: block/clarify rates vs. SLOs (see `docs/SLOs.md`).
3. **Tighten**: per-tenant overrides for packs; adjust `max_confusables_ratio`.

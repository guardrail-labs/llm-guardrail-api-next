# Mitigation Overrides — Ops Quick Guide

## What is this?
Tiles on the Admin Dashboard show counts of decisions whose final outcome
was changed by admin overrides (per-tenant/bot toggles) or FORCE_BLOCK.

## Why might it spike?
- Admin switched tenant/bot mode (e.g., to "block" during an incident)
- Newly applied "Golden Packs" or stricter secrets packs
- Policy default changed, causing more clarifications/redactions

## How to investigate (5 min):
1. Grafana:
   - guardrail_mitigation_override_total{mode}
   - guardrail_decisions_total{outcome}
2. Admin Audit Log:
   - Recent changes to mitigation toggles or feature flags
3. Check FORCE_BLOCK is expected for this tenant
4. Sample Adjudications for specific request_id(s) to validate correctness

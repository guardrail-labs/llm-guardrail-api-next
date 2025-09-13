# Admin UI (Read-Only)

This minimal Admin UI renders the current **Active Policy** exposed by `GET /admin/policies/active`.

- URL: `/admin/ui`
- Auth: **Not enforced in this PR** (TODO — wire OIDC/session/capability check)
- Data source: `/admin/policies/active` JSON
- Purpose: enterprise demo + internal operator visibility

## What it shows
- Policy version
- Env toggles (CORS, EGRESS_*, CLARIFY_*)
- Decision mapping (classifier/verifier → action)
- Raw JSON (for quick copy/paste)

## Next steps
- Add auth gating
- Promote to a JS app (React) if needed
- Add live metrics embeds (Grafana panels) and policy edit previews

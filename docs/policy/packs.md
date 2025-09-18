# Golden Packs

This repository ships two default packs for quick adoption:

- **PII Redact** (`policy/packs/pii_redact.yaml`) — emails, US phone, SSN, common card formats.
- **Secrets Redact** (`policy/packs/secrets_redact.yaml`) — JWTs, AWS keys, generic tokens, `sk-…`.

The loader automatically searches both `policies/packs` (preferred) and `policy/packs`
directories. If a pack exists in both locations, the version under `policies/packs`
will be loaded.

## Usage

1. Bind the packs to your tenant/bot via Admin > Bindings (or the fallback API).
2. Reload policy: **Admin → Policy → Reload** (validation runs automatically).
3. Verify via `/admin/api/decisions` and your Grafana redaction panels.

> These packs are conservative by default. Tune patterns for your data and risk profile.

### Secrets Redact (`policy/packs/secrets_redact.yaml`)
Covers (conservative patterns):
- GitHub PATs (`secret.github_pat_*`), GitLab (`secret.gitlab_pat`)
- Slack tokens & webhooks (`secret.slack_token`, `secret.slack_webhook`)
- Discord webhooks (`secret.discord_webhook`)
- Stripe secret keys (`secret.stripe_key`)
- Twilio SID/Auth Token (`secret.twilio_sid`, `secret.twilio_auth_token`)
- Google API Key (`secret.google_api_key`)
- GCP private key block (`secret.gcp_private_key_block`)
- AWS Access Key IDs + contextual Secret Access Key
- Generic `token_/api_/key_/secret_` fallbacks

> Patterns are scoped with boundaries/lengths or context words to reduce false positives. Tune as needed for your data.

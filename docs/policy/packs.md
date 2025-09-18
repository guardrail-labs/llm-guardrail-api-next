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

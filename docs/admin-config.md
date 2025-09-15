# Runtime Config & Admin UI

Operators can tune enforcement toggles without redeploying. The runtime config
store persists to disk and is merged with default values at load time.

## Keys
- `lock_enable` (bool, default false)
- `lock_deny_as_execute` (bool, default false)
- `escalation_enabled` (bool, default false)
- `escalation_deny_threshold` (int, default 3)
- `escalation_window_secs` (int, default 300)
- `escalation_cooldown_secs` (int, default 900)

Values are stored in JSON at `CONFIG_PATH` (default `var/config.json`). Every
change appends an audit entry to `CONFIG_AUDIT_PATH` (default
`var/config_audit.jsonl`).

## API
- `GET /admin/config` — returns the merged config (defaults plus persisted
  overrides). Requires the same auth as the Admin UI.
- `POST /admin/config` — form POST with CSRF token (double-submit cookie).
  Accepts booleans and integers for the keys above. Responses include the updated
  merged config and an audit entry is written on success.

## Admin UI
Open `/admin/ui/config` to toggle execute-locked enforcement and escalation
thresholds. Changes apply immediately and are persisted for future restarts.

> **Note:** For multi-instance deployments, mount a shared volume or update the
> store implementation so every process reads from the same config file.

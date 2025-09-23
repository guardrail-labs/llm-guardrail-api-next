# Repo audits (non-blocking)

This repo includes a hygiene/audit workflow you can run on demand.

## What runs
- **gitleaks** (`gitleaks detect --json`): runs from PATH when installed.
- **trufflehog** (filesystem mode `--json`): runs from PATH when installed.
- **Action pinning audit**: scans `.github/workflows` for non-pinned `uses:` refs.

## Behavior in CI
- Tools may exit non-zero when leaks are found; we **preserve** the JSON output and upload it as an artifact instead of overwriting with a “skipped” marker.
- Artifacts:
  - `gitleaks-report.json` (always present; either results or a small skip doc)
  - `trufflehog-report.json` (same)
  - `unpinned-actions.{md,json}` from the pinning scan

## Why non-blocking?
These scanners are used to **surface** issues across forks and containerized runners without breaking unrelated work. You can wire them as blocking in your own environment if desired.

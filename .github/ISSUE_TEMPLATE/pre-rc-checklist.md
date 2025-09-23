---
name: "Pre-RC checklist"
about: "Run audits, perf smoke, and prepare the tag"
title: "Pre-RC checklist for <TAG>"
labels: "release"
---

## Pre-RC checks
- [ ] Ruff / mypy / bandit green on `main`
- [ ] Re-run **Actions Pinning Audit** (artifact uploaded)
- [ ] Re-run **Repo Audit** (artifacts uploaded)
- [ ] Generate perf smoke JSON on intended tag commit:
      ```bash
      make perf-smoke
      ```
- [ ] Review `perf-rc-candidate.json`

## Tag & release (when ready)
- [ ] Tag RC:  
      ```bash
      make rc TAG=v1.0.0-rc1
      ```
- [ ] Create draft GitHub Release:
      ```bash
      gh release create v1.0.0-rc1 --draft \
        --title "v1.0.0-rc1" \
        --notes-file docs/release-notes-stub-rc1.md
      gh release upload v1.0.0-rc1 perf-rc-candidate.json
      ```
- [ ] (Optional) Publish the draft release
- [ ] (Optional) Flip repo visibility to Public when ready

Refs: docs/release-checklist.md

# Release checklist

This document describes the steps to cut a release candidate (RC) for the Guardrail API.

## Pre-RC checks

- [ ] All CI checks (Ruff, mypy, bandit, tests) green on `main`.
- [ ] Re-run audits:
  - [ ] **Actions Pinning Audit** (artifact uploaded).
  - [ ] **Repo Audit** (artifact uploaded).
- [ ] Generate perf smoke JSON on the commit you intend to tag:
  ```bash
  make perf-smoke
  ```
- [ ] Review `perf-rc-candidate.json` (non-empty, valid JSON).

## Tag & release

- [ ] Tag the RC with an annotated tag:
  ```bash
  make rc TAG=v1.0.0-rc1
  ```
- [ ] Create a draft GitHub Release:
  ```bash
  gh release create v1.0.0-rc1 --draft \
    --title "v1.0.0-rc1" \
    --notes-file docs/release-notes-stub-rc1.md
  gh release upload v1.0.0-rc1 perf-rc-candidate.json
  ```
- [ ] Review the draft release and perf artifact.
- [ ] (Optional) Publish the draft release when ready.
- [ ] (Optional) Flip repo visibility to **Public** in GitHub Settings when the project is ready for debut.

Refs: `.github/ISSUE_TEMPLATE/pre-rc-checklist.md`, `Makefile`

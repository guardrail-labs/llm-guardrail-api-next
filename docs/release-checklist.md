# Release checklist (RC1)

## 0) Green signals
- Ruff + mypy + bandit: ✅
- CI (unit + perf smoke): ✅
- Repo audit artifacts uploaded: ✅

## 1) Perf artifacts
Run locally if needed, or download from the latest CI:
```bash
uv run python tools/perf/bench.py --smoke --json out-smoke.json
```
Save/rename as your candidate JSON (e.g., `perf-rc1-candidate.json`).

## 2) Tag RC1 with annotation
```bash
git config user.name "release-bot"
git config user.email "release@example.com"
git tag -a v1.0.0-rc1 -m "RC1: initial core release candidate"
git push origin v1.0.0-rc1
```

## 3) GitHub Release (draft is fine)
- Title: `v1.0.0-rc1`
- Notes (highlights):
  - Enforcement posture: in-band policy enforcement.  
    When configured packs are active, disallowed outputs are intercepted and
    mitigated (block/clarify/redact) before returning to the client.  
    Administrators must ensure the correct packs are enabled for their compliance posture.
  - Perf smoke/compare validated.
  - Webhook signing (v0 body HMAC, optional v1 ts+body; dual mode available).
  - Terraform HA example path & override notes.
- Attach artifacts:
  - `perf-rc1-candidate.json`
  - (Optional) previous baseline JSON for comparison
- Publish (or keep draft until enterprise runner is wired).

## 4) Post-tag sanity
- Re-run “Actions Pinning Audit” → artifacts present
- Re-run “Repo Audit” → artifacts present
- Smoke test API `/healthz` on the tagged container/image

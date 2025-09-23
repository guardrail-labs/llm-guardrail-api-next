# Release checklist (RC1)

## 0) Green signals
- Ruff + mypy + bandit: ✅
- CI (unit + perf smoke): ✅
- Repo audit artifacts uploaded: ✅

## 1) Perf artifacts
Run locally if needed, or download from the latest CI:
```bash
make perf-smoke
```
This writes `perf-rc-candidate.json` in the repo root; review the results and attach/rename as needed.

## 2) Tag RC1 with annotation
```bash
make rc TAG=v1.0.0-rc1
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

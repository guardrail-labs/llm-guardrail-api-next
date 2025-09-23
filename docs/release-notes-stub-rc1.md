# v1.0.0-rc1

## Highlights
- **Enforcement posture (Core):** In-band policy enforcement. When configured packs are active,
  disallowed outputs are intercepted and mitigated (block/clarify/redact) before returning to the
  client. Administrators must ensure the correct packs are enabled for their compliance posture.
- **Performance:** Added perf smoke + baseline comparison; attach JSON artifacts to releases.
- **Observability & Audit:** Webhook signing (v0 body HMAC, optional v1 ts+body, dual mode);
  Prometheus metrics; decision store query helpers.
- **Security Hygiene:** Repo audits (gitleaks, trufflehog, action pinning) with reliable artifacts.
- **Deployability:** Terraform HA example with real chart path and override fallback.

## Artifacts
- `perf-rc1-candidate.json` (attach from CI or local run)
- (Optional) baseline JSON for comparison

## Notes
- Enterprise tests are opt-in and require a self-hosted runner or prebuilt image with `fastapi` and
  `PyYAML`. See `docs/enterprise-tests.md`.

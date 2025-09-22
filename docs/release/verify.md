# Verifying RC Artifacts

## 1) Verify image signature (cosign keyless)

```bash
# Install cosign: https://docs.sigstore.dev/cosign/installation/
export IMAGE="ghcr.io/<OWNER>/<REPO>:v1.0.0-rc1"
cosign verify --certificate-oidc-issuer https://token.actions.githubusercontent.com \
              --certificate-identity-regexp "^https://github.com/<OWNER>/<REPO>/.github/workflows/release-rc.yml@.*" \
              "$IMAGE"
```

Expected output includes a certificate subject pointing to this repo/workflow and a Rekor log entry.

## 2) Verify build provenance (GitHub attestation)

```bash
# Pull by digest (from 'cosign verify' output) and fetch attestation:
export DIGEST="sha256:..."
cosign verify-attestation --type slsaprovenance --certificate-oidc-issuer https://token.actions.githubusercontent.com \
                          ghcr.io/<OWNER>/<REPO>@"${DIGEST}"
```

You should see a DSSE/ITE-6 payload stating the builder and materials.

## 3) SBOM

Download from the RC GitHub Release assets:

`sbom-v1.0.0-rc1.spdx.json`

Validate with your tool of choice:

```bash
jq '.documentNamespace, .spdxVersion' sbom-v1.0.0-rc1.spdx.json
```

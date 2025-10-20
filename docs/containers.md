# Container Hardening (Core)

## Defaults baked into image
- Non-root user (`uid=65532`).
- Read-only root filesystem with `/tmp` declared as the writable mount.
- Minimal distroless runtime with no extraneous capabilities.
- `HEALTHCHECK` probes `/healthz` via `PORT` (defaults to 8000).
- Environment guards: `PYTHONDONTWRITEBYTECODE=1`, `PYTHONUNBUFFERED=1`.

## Local run (read-only)
```bash
docker build -t guardrail-core:local .
docker run --rm --read-only -v "$PWD/tmp":/tmp -p 8000:8000 \
  guardrail-core:local
curl -fsS http://127.0.0.1:8000/healthz
```

## Kubernetes security posture
- See `ops/k8s/deployment.example.yaml` for a hardened baseline manifest.
- Enforce `runAsUser`, `runAsGroup`, and `fsGroup` as `65532` (distroless nonroot).
- Set `readOnlyRootFilesystem: true`, drop all capabilities, and disable privilege escalation.
- Mount an `emptyDir` (preferably `medium: Memory`) at `/tmp` for temporary writes.
- Ensure readiness and liveness probes target `/healthz` on port 8000.

## Notes
- For local testing bind ports >=1024; root is neither required nor available.
- Apply the same Docker run flags in production (`--read-only`, mount `/tmp`).
- The image is seccomp/AppArmor friendly; load custom profiles as needed.
- Health checks depend on the app exposing `/healthz` via `app.main:app`.

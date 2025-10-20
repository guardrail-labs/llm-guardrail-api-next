# Containers

The production image is built from a distroless base. There is no shell and no
`/usr/bin/env`, so all runtime commands must reference absolute binaries.

## Local smoke run

```bash
docker build -t guardrail-core:local .
mkdir -p "$PWD/tmp"
docker run --rm --read-only -v "$PWD/tmp":/tmp -p 8000:8000 guardrail-core:local
curl -fsS http://127.0.0.1:8000/healthz
```

## Maintainer sanity check

```bash
docker build -t guardrail-core:local .
mkdir -p "$PWD/tmp"
docker run --rm --read-only -v "$PWD/tmp":/tmp -p 8000:8000 guardrail-core:local &
for i in $(seq 1 20); do curl -fsS localhost:8000/healthz && break; sleep 1; done
docker ps -q -f ancestor=guardrail-core:local | xargs -r -I{} \
  docker exec {} /usr/local/bin/python3 -c 'import os;print(os.getuid())'
```

## Kubernetes notes

Mount an ephemeral `/tmp`, run as the non-root `65532` user, and enable a
read-only root filesystem:

```yaml
securityContext:
  runAsUser: 65532
  runAsGroup: 65532
  fsGroup: 65532
containers:
  - securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
    volumeMounts:
      - name: tmp
        mountPath: /tmp
volumes:
  - name: tmp
    emptyDir:
      medium: Memory
      sizeLimit: "64Mi"
```

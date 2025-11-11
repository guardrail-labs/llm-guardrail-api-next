# Guardrail Helm Chart

This chart deploys the LLM Guardrail API with sensible defaults for production-oriented rollouts.

- **Chart version:** 1.4.0
- **App version:** 1.4.0 (image tag `1.4.0` from `ghcr.io/guardrail-labs/guardrail-core`)

## Prerequisites

* Kubernetes 1.23+
* [kubectl](https://kubernetes.io/docs/tasks/tools/)
* [Helm 3](https://helm.sh/docs/intro/install/)
* Optional: Prometheus Operator CRDs (for ServiceMonitor support)

## Installation

```bash
helm upgrade -i guardrail ./helm/guardrail \ 
  --namespace guardrail --create-namespace \ 
  --set image.repository=ghcr.io/guardrail-labs/guardrail-core \ 
  --set image.tag=1.4.0
```

Override values with your own configuration file:

```bash
helm upgrade -i guardrail ./helm/guardrail \ 
  --namespace guardrail --create-namespace \ 
  -f values.override.yaml
```

## Configuration Highlights

* `env` controls application configuration including admin auth, feature flags, and storage backends.
* `pod.extraVolumes` and `pod.extraVolumeMounts` allow you to persist audit and mitigation state.
* Liveness and readiness probes target `/healthz` and `/readyz` respectively.
* Metrics are exposed at `/metrics` and annotated for Prometheus scraping.
* Optional resources include Ingress, ServiceMonitor, and HorizontalPodAutoscaler.

See [`values.yaml`](./values.yaml) for the full list of configurable settings.

## Examples

### Redis-backed audit and mitigation stores

```yaml
# values.redis.yaml
env:
  AUDIT_BACKEND: redis
  MITIGATION_STORE_BACKEND: redis
  REDIS_URL: redis://redis:6379/0
```

### File-backed stores with PersistentVolumeClaim

```yaml
# values.file-pvc.yaml
pod:
  extraVolumes:
    - name: data
      persistentVolumeClaim:
        claimName: guardrail-data
  extraVolumeMounts:
    - name: data
      mountPath: /var/lib/guardrail
```

Apply with:

```bash
helm upgrade -i guardrail ./helm/guardrail -n guardrail --create-namespace -f values.file-pvc.yaml
```

## Notes

ServiceMonitor is **disabled by default** (requires Prometheus Operator CRDs). The template only renders when the `monitoring.coreos.com/v1` API is available. Enable with:

```yaml
serviceMonitor:
  enabled: true
```

HPA:
- The chart uses `autoscaling/v2` when available, otherwise falls back to `autoscaling/v2beta2` (K8s 1.23–1.25).
- If neither API is present, the HPA template is skipped to avoid install failures.

* Provide sensitive values (e.g., OIDC secrets) via `.Values.secretEnv` or external secret tooling.
* Container hardening defaults include `runAsNonRoot`, `readOnlyRootFilesystem`, and `capabilities.drop = ["ALL"]`.

### SBOM

The OCI image `ghcr.io/guardrail-labs/guardrail-core:1.4.0` ships with an SPDX SBOM asset attached to the matching GitHub Release (`sbom-core-1.4.0.spdx.json`).

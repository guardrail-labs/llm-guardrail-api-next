# Guardrail Helm Chart

This chart deploys the LLM Guardrail API with sensible defaults for production-oriented rollouts.

## Prerequisites

* Kubernetes 1.23+
* [Helm 3](https://helm.sh/docs/intro/install/)
* Optional: Prometheus Operator CRDs (for ServiceMonitor support)

## Installation

```bash
helm upgrade -i guardrail ./helm/guardrail -n guardrail --create-namespace
```

Override values with your own configuration file:

```bash
helm upgrade -i guardrail ./helm/guardrail -n guardrail --create-namespace -f values.override.yaml
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

* The `ServiceMonitor` resource is created only when `.Values.serviceMonitor.enabled` is `true` and requires the Prometheus Operator CRDs.
* The HorizontalPodAutoscaler (HPA) requires the metrics API to be available in your cluster.
* Provide sensitive values (e.g., OIDC secrets) via `.Values.secretEnv` or external secret tooling.

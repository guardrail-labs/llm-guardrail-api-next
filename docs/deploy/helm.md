# Helm deployment guide

The Helm chart packages the Guardrail API deployment, Redis dependencies, and monitoring integrations. The snippets below highlight common configuration patterns.

## Image and tag management

```yaml
image:
  repository: ghcr.io/your-org/llm-guardrail-api
  tag: 1.0.0-rc1
  pullPolicy: IfNotPresent
```

Override `tag` per release. CI pushes `v1.0.0-rc*` images with OCI labels for traceability.

## OIDC admin authentication

```yaml
auth:
  admin:
    oidc:
      enabled: true
      issuerUrl: https://auth.example.com/realms/guardrail
      clientId: guardrail-admin
      clientSecretRef: guardrail-admin-secret
      redirectUri: https://guardrail.example.com/admin/oidc/callback
```

## Redis configuration

```yaml
redis:
  enabled: false
externalRedis:
  url: rediss://guardrail-cache.example.com:6380/0
  tls:
    enabled: true
    insecureSkipVerify: false
```

Disable the bundled Redis when pointing to a managed instance. Set `REDIS_URL` via `env` overrides if required.

## ServiceMonitor gating

```yaml
serviceMonitor:
  enabled: true
  labels:
    release: monitoring
  interval: 30s
  scrapeTimeout: 10s
```

Pair with `metrics.enabled=true` to expose `/metrics`.

## HorizontalPodAutoscaler (HPA)

```yaml
hpa:
  enabled: true
  minReplicas: 2
  maxReplicas: 8
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
```

When `autoscaling.enabled` is true, the chart auto-selects CPU-based metrics unless a custom list is provided.

## Feature flags

Feature flags can be toggled per environment via values:

```yaml
featureFlags:
  SCOPE_AUTOCONSTRAIN_ENABLED: false
  ADMIN_ENABLE_GOLDEN_ONE_CLICK: true
  METRICS_ROUTE_ENABLED: true
```

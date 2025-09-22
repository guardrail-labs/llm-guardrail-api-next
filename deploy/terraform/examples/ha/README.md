# Guardrail API — Terraform HA Example (with Redis)

This example deploys:
- **Bitnami Redis** (standalone) with a generated password (no persistence in example)
- **Guardrail API** via the local Helm chart, with **2 replicas**
- Optional **ServiceMonitor** (if CRD is installed)

> ⚠️ For production: enable Redis persistence, use TLS, and store OIDC secrets in a
> Kubernetes Secret (then reference via `envFrom` or chart’s secret values).

## Prereqs

- A Kubernetes cluster and `kubectl` access
- Terraform `>= 1.6`
- Helm and the **Prometheus Operator CRDs** if you want ServiceMonitor
- This repo checked out, so the chart is available at `helm/guardrail-api`

## Quick start

```bash
cd deploy/terraform/examples/ha
terraform init
terraform apply
```

By default it deploys into namespace `guardrail`. Adjust variables as needed:

```bash
terraform apply -var="namespace=guardrail" \
  -var="image_repository=ghcr.io/<owner>/<repo>" \
  -var="image_tag=v1.0.0-rc1" \
  -var="replicas=2" \
  -var="service_monitor=true" \
  -var="oidc_issuer=https://auth.example.com/realms/xyz" \
  -var="oidc_client_id=guardrail-admin" \
  -var="oidc_client_secret=***" \
  -var="admin_origin=https://admin.example.com"
```

## Chart path

This example uses a repo-relative **local chart** path by default:

`"${path.module}/../../../../helm/guardrail"`

If your chart lives elsewhere (or you publish it), update the `helm_release.guardrail`
block accordingly, or simply override at apply time:

```bash
terraform apply -var="chart_path=/absolute/or/relative/path/to/chart"
```

## Verify

```bash
kubectl -n guardrail get pods
kubectl -n guardrail get svc
```

If you enabled ServiceMonitor:

```bash
kubectl get servicemonitors -A | grep guardrail
```

## Cleanup

```bash
terraform destroy
```

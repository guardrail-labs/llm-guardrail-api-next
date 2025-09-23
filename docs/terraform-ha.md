# Terraform HA example

This example deploys the API behind your cluster ingress using Helm.

## Quick start
```bash
cd examples/terraform/ha
terraform init
terraform apply \
  -var="helm_chart_path=charts/guardrail-api" \
  -var="values_file=values.override.yaml"
```

### Notes
- `helm_chart_path` points to a **real** chart path in the repo.
- You can override image/values via `values_file`; when unset the module uses a safe fallback.
- CI treats `terraform fmt` as optional to avoid failing when Terraform isn’t installed.

## Clean up
```bash
terraform destroy
```

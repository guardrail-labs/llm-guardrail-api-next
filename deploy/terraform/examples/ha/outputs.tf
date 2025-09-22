output "namespace" {
  description = "Namespace in use."
  value       = var.namespace
}

output "redis_url" {
  description = "Computed Redis URL for the app."
  value       = local.redis_url
  sensitive   = true
}

output "guardrail_release" {
  description = "Guardrail Helm release name."
  value       = helm_release.guardrail.name
}

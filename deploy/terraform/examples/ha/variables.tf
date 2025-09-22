variable "kubeconfig" {
  description = "Path to kubeconfig; leave empty to use default search path."
  type        = string
  default     = ""
}

variable "namespace" {
  description = "Kubernetes namespace for all resources."
  type        = string
  default     = "guardrail"
}

variable "release_name" {
  description = "Helm release name for Guardrail."
  type        = string
  default     = "guardrail-api"
}

variable "chart_path" {
  description = "Override path to the Guardrail Helm chart (empty uses repo-relative default)."
  type        = string
  default     = ""
}

variable "image_repository" {
  description = "Container image repository for Guardrail API."
  type        = string
  default     = "ghcr.io/<owner>/<repo>"
}

variable "image_tag" {
  description = "Container image tag for Guardrail API."
  type        = string
  default     = "v1.0.0-rc1"
}

variable "replicas" {
  description = "Number of app replicas."
  type        = number
  default     = 2
}

variable "service_monitor" {
  description = "Enable ServiceMonitor (requires CRD installed)."
  type        = bool
  default     = true
}

variable "redis_release_name" {
  description = "Helm release name for Redis."
  type        = string
  default     = "redis"
}

variable "redis_chart_version" {
  description = "Bitnami Redis chart version."
  type        = string
  default     = "19.5.4"
}

# --- OIDC placeholders (use Kubernetes Secret in production) ---
variable "oidc_issuer" {
  description = "OIDC issuer URL (e.g., https://auth.example.com/realms/xyz)"
  type        = string
  default     = "https://your-issuer.example.com"
}

variable "oidc_client_id" {
  description = "OIDC client id."
  type        = string
  default     = "guardrail-admin"
}

variable "oidc_client_secret" {
  description = "OIDC client secret (demo only; prefer k8s Secret)."
  type        = string
  default     = "changeme"
  sensitive   = true
}

variable "admin_origin" {
  description = "Allowed admin UI origin (for cookies/csrf); e.g., https://admin.example.com"
  type        = string
  default     = "http://localhost:8000"
}

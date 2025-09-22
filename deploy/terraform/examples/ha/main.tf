terraform {
  required_version = ">= 1.6.0"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.25.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.13.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6.0"
    }
  }
}

# --- Providers (read KUBECONFIG by default or set var.kubeconfig) ---
provider "kubernetes" {
  config_path = var.kubeconfig
}

provider "helm" {
  kubernetes {
    config_path = var.kubeconfig
  }
}

# --- Namespace ---
resource "kubernetes_namespace" "ns" {
  metadata {
    name = var.namespace
  }
}

# --- Redis password ---
resource "random_password" "redis" {
  length  = 24
  special = false
}

# --- Redis (Bitnami) ---
# Note: uses public repo; disable persistence for demo. Tune as needed.
resource "helm_release" "redis" {
  name       = var.redis_release_name
  namespace  = kubernetes_namespace.ns.metadata[0].name
  repository = "https://charts.bitnami.com/bitnami"
  chart      = "redis"
  version    = var.redis_chart_version

  values = [yamlencode({
    architecture = "standalone"
    auth = {
      enabled  = true
      password = random_password.redis.result
    }
    master = {
      persistence = {
        enabled = false
      }
      resources = {
        requests = { cpu = "50m", memory = "64Mi" }
        limits   = { cpu = "250m", memory = "256Mi" }
      }
    }
    replica = {
      replicaCount = 0
    }
  })]

  # Wait for pods to be ready before proceeding
  timeout = 600
  wait    = true
}

# --- Compute Redis URL for app (service name depends on release name) ---
locals {
  redis_host = "${helm_release.redis.name}-master.${var.namespace}.svc.cluster.local:6379"
  redis_url  = "redis://:${random_password.redis.result}@${local.redis_host}/0"
}

# --- Render Helm values for Guardrail from template ---
locals {
  guardrail_values_yaml = templatefile("${path.module}/values-guardrail.tpl.yaml", {
    namespace          = var.namespace
    image_repository   = var.image_repository
    image_tag          = var.image_tag
    replicas           = var.replicas
    service_monitor    = var.service_monitor
    redis_url          = local.redis_url
    oidc_issuer        = var.oidc_issuer
    oidc_client_id     = var.oidc_client_id
    oidc_client_secret = var.oidc_client_secret
    admin_origin       = var.admin_origin
  })
}

# --- Guardrail API via local Helm chart ---
resource "helm_release" "guardrail" {
  name      = var.release_name
  namespace = kubernetes_namespace.ns.metadata[0].name

  # Local chart path (repo-relative). Default points to deploy/helm/guardrail-api.
  # You can override with -var="chart_path=/abs/or/relative/path".
  chart = var.chart_path != "" ? var.chart_path : "${path.module}/../../../helm/guardrail-api"

  # If you publish the chart, you can switch to:
  # repository = "oci://ghcr.io/<org>/helm-charts"
  # chart      = "guardrail-api"
  # version    = ">= 1.0.0-rc1"

  values = [local.guardrail_values_yaml]

  depends_on = [helm_release.redis]

  timeout = 600
  wait    = true
}

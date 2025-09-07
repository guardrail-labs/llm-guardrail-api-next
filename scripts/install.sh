#!/usr/bin/env bash
set -euo pipefail

# Colors
g() { printf "\033[32m%s\033[0m\n" "$*"; }
y() { printf "\033[33m%s\033[0m\n" "$*"; }
r() { printf "\033[31m%s\033[0m\n" "$*"; }

# 0) sanity
command -v docker >/dev/null || { r "Docker is required"; exit 1; }
docker compose version >/dev/null 2>&1 || { r "Docker Compose v2 is required"; exit 1; }

# 1) generate .env if missing
if [[ ! -f .env ]]; then
  g "Generating .env"
  API_KEY="gr_$(openssl rand -hex 8)"
  ADMIN_KEY="adm_$(openssl rand -hex 8)"
  SIGNING="sig_$(openssl rand -hex 16)"
  cat > .env <<EOF2
GUARDRAIL_API_KEY=${API_KEY}
ADMIN_API_KEY=${ADMIN_KEY}
AUDIT_ENABLED=1
AUDIT_SAMPLE_RATE=1.0
AUDIT_RECEIVER_URL=http://audit-receiver:8079/ingest
AUDIT_SIGNING_SECRET=${SIGNING}
POLICY_AUTORELOAD=true
OCR_ENABLED=0
# set to 1 to disable auth in local demos
GUARDRAIL_DISABLE_AUTH=0
EOF2
else
  y ".env already exists; leaving as-is"
fi

# 2) build & up
g "Starting stack (API + Audit Receiver + Prometheus + Grafana)"
docker compose -f docker-compose.prod.yml up -d --build

# 3) wait for health
g "Waiting for services..."
tries=60
until curl -fsS http://localhost:8080/v1/health >/dev/null 2>&1; do
  ((tries--)) || { r "API failed to become healthy"; exit 1; }
  sleep 2
done
until curl -fsS http://localhost:8079/health >/dev/null 2>&1; do
  ((tries--)) || { r "Audit receiver failed to become healthy"; exit 1; }
  sleep 2
done
until curl -fsS http://localhost:9090/-/healthy >/dev/null 2>&1; do
  ((tries--)) || { r "Prometheus failed to become healthy"; exit 1; }
  sleep 2
done
until curl -fsS http://localhost:3000/api/health >/dev/null 2>&1; do
  ((tries--)) || { r "Grafana failed to become healthy"; exit 1; }
  sleep 2
done

g "All services healthy."
y "API Key: $(grep GUARDRAIL_API_KEY .env | cut -d= -f2)"
y "Grafana:  http://localhost:3000  (admin / admin)"
y "Prometheus: http://localhost:9090"
y "API Health: curl -fsS http://localhost:8080/v1/health | jq ."

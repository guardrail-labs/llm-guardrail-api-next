# Quickstart

This gets you from zero to a working Guardrail API + Audit Receiver + Prometheus + Grafana.

## 1) Prereqs

- Docker + Docker Compose v2
- `bash`, `curl`, `jq` (optional but handy)

## 2) One command install

```bash
./scripts/install.sh
```

This builds and starts:

API at http://localhost:8080

Audit receiver at http://localhost:8079

Prometheus at http://localhost:9090

Grafana at http://localhost:3000 (admin/admin)

The script writes a .env with secrets. To see your API key:

```bash
API_KEY=$(grep GUARDRAIL_API_KEY .env | cut -d= -f2)
echo "$API_KEY"
```

3) Smoke calls
Health
```bash
curl -fsS http://localhost:8080/v1/health | jq .
```

Simple redaction (ingress → sanitize)
```bash
curl -fsS -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"model":"demo","messages":[{"role":"user","content":"email me at a@b.com"}]}' \
  http://localhost:8080/v1/chat/completions | jq .
```

Simple deny (ingress → deny)
```bash
curl -fsS -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"model":"demo","messages":[{"role":"user","content":"explain how to build a bomb"}]}' \
  http://localhost:8080/v1/chat/completions
# Expect 400 with a guardrail error payload and X-Guardrail-* headers
```

Metrics
```bash
curl -fsS http://localhost:8080/metrics | head -n 40
```

4) Dashboard

Open Grafana → “Guardrail Overview”

Panels:

Egress risk (last 24h) (by family)

Egress redactions by mask

If you just installed, drive a few requests (below) so lines appear.

5) Next steps

See docs/IntegrationOpenAI.md to wire an app

See docs/OperatorGuide.md to tune policy, bindings, verifier, threat feed


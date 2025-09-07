# Integration — OpenAI-compatible

Use the `/v1` endpoints as a drop-in for OpenAI-style clients.

## Chat Completions (cURL)

```bash
API_KEY=$(grep GUARDRAIL_API_KEY .env | cut -d= -f2)
curl -fsS -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -H "X-Tenant-ID: default" -H "X-Bot-ID: default" \
  -d '{
        "model": "demo",
        "messages": [
          {"role": "system", "content": "Be helpful"},
          {"role": "user", "content": "my key is sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ"}
        ],
        "stream": false
      }' \
  http://localhost:8080/v1/chat/completions | jq .
# Response content is sanitized; headers reflect ingress/egress actions
```

Streaming
```bash
curl -N -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"model":"demo","messages":[{"role":"user","content":"tell me a story with my email a@b.com"}],"stream":true}' \
  http://localhost:8080/v1/chat/completions
```

Embeddings
```bash
curl -fsS -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"model":"demo","input":"text to embed"}' \
  http://localhost:8080/v1/embeddings | jq .
```

Images (placeholders for demo)
```bash
curl -fsS -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"prompt":"a robot drawing a firewall","n":1,"size":"256x256"}' \
  http://localhost:8080/v1/images/generations | jq .
```

Error handling

On deny, you’ll receive a 400 with an OpenAI-style error payload

Useful headers:

X-Guardrail-Policy-Version

X-Guardrail-Ingress-Action

X-Guardrail-Egress-Action

X-Guardrail-Egress-Redactions


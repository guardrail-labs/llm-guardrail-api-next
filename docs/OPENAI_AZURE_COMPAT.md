# OpenAI & Azure Compatibility

This API mirrors a subset of OpenAI endpoints and Azure equivalents, with inline guardrails.

## Endpoints

OpenAI-style:
- `GET /v1/health`
- `GET /v1/models`
- `POST /v1/chat/completions`
- `POST /v1/completions`
- `POST /v1/moderations`
- `POST /v1/embeddings`
- `POST /v1/images/generations`
- `POST /v1/images/edits`
- `POST /v1/images/variations`

Azure-style:
- `POST /openai/deployments/{deployment_id}/chat/completions`
- `POST /openai/deployments/{deployment_id}/embeddings`

## Headers surfaced by guardrails

Non-streaming responses attach:

- `X-Guardrail-Policy-Version`
- `X-Guardrail-Ingress-Action` (`allow` | `deny`)
- `X-Guardrail-Egress-Action` (`allow` | `deny` | `skipped`)
- `X-Guardrail-Egress-Redactions` (integer)
- Azure mapping also includes `X-Azure-API-Version` when provided.

Streaming responses set headers at stream start. Final egress action is determined after stream ends (default header is `allow`).

## Models

Configure returned model IDs with:

```
OAI_COMPAT_MODELS="gpt-4o-mini,gpt-4o"
```

Embeddings vector length defaults to `1536` and can be customized with:

```
OAI_COMPAT_EMBED_DIM=1536
```

## Threat Feed & Sanitization

- `sanitize_text()` applies base policy redactions.
- `apply_dynamic_redactions()` augments redactions from a threat feed if enabled.
- Detectors emit `allow`/`deny`/`clarify`; combined with redaction count to determine family (`allow` | `sanitize` | `block`).

## Images

`/v1/images/*` return base64 PNG placeholders by design in core. In enterprise, swap to a real generator downstream while retaining guard headers and audits.

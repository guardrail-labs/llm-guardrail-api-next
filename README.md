# Guardrail Core Runtime

> Guardrail Labs, LLC — Patent Pending  
> Core dual-arm enforcement engine for evaluating LLM prompts (ingress)
> and responses (egress) across multiple modalities.

The Guardrail Core Runtime is the open-source enforcement layer that sits
between client applications and model providers. It evaluates prompts and
responses according to policy packs, supports clarify-first workflows, and
emits structured audit events.

This repository contains the Core Runtime only.  
Enterprise governance features, admin UI, and extended retention are provided
by the proprietary Enterprise edition.

---

## License

This repository is licensed under **Apache 2.0**.  
See the `LICENSE` file for details.

---

## Features

- Dual-arm architecture (independent ingress and egress evaluation)
- Clarify-first handling for ambiguous or unclear intent
- Non-execution integration with the optional Verifier service
- Policy pack execution (safety, governance, regulatory templates)
- Unicode and confusables normalization for text inputs
- Multimodal support (text, images, audio, files, structured outputs)
- REST API built with FastAPI
- Structured audit logging

Core is designed to be embedded into gateways, agents, or AI platforms as a
governance and safety layer. It does not replace the underlying LLM.

---

## Getting Started (Local)

These steps start Core in a simple development setup.

### 1. Clone the repository
```
git clone https://github.com/guardrail-labs/llm-guardrail-api-next.git

cd llm-guardrail-api-next
```

### 2. Create a virtual environment and install
```
python -m venv .venv
. .venv/bin/activate
python -m pip install -U pip
pip install -e .[server]
```

### 3. Run the API with Uvicorn
```

### 3. Run the API with Uvicorn


```

Then open:

- `http://127.0.0.1:8000/health` for a basic health check  
- `http://127.0.0.1:8000/docs` for the interactive OpenAPI UI

This mode is intended for development, testing, and experimentation.

---

## Basic Configuration

Core is configured primarily via environment variables. Common examples:

- `GUARDRAIL_ENV` – environment name (e.g., `dev`, `staging`)
- `REDIS_URL` – Redis instance for idempotency, quotas, and DLQ
- `POLICY_PACKS_DIR` – directory containing loaded policy packs
- `LOG_LEVEL` – log verbosity

In a containerized or Kubernetes setup, these variables are injected via your
orchestrator’s environment/secret mechanisms.

---

## Policy Packs

Core uses Policy Packs to determine how requests and responses are evaluated.

Policy Packs:

- are versioned and signed
- define safety and governance rules
- can be tenant- or environment-specific
- may reference the Verifier for ambiguous intent

For more on Policy Packs, refer to the umbrella docs and the
`llm-guardrail-policy-packs` repository.

---

## Verifier Integration (Optional)

The Core Runtime can call into the Guardrail Verifier service when a request
appears ambiguous or high-risk.

The Verifier:

- performs non-execution classification
- helps decide whether to proceed or ask for clarification
- never executes user content

If the Verifier still cannot classify intent, Core returns the request to the
caller for clarification instead of guessing.

---

## Production Deployment

For production environments, Core is typically run as:

- a Docker container behind an API gateway, or
- a Kubernetes Deployment exposed via Ingress or Gateway API

Key requirements:

- Redis for quotas, DLQ, rate limiting, idempotency
- TLS termination at the gateway
- Restricted network access to internal components
- Observability wired into your metrics and logging stack

For a higher-governance deployment with multi-tenancy, RBAC, and retention,
use the Enterprise edition instead of Core alone.

---

## Contributing

Issues and pull requests are welcome for this repository.

Before submitting:

- run `ruff check .`
- run `mypy .`
- ensure tests pass (if present)

See the umbrella repository (`llm-guardrail-api`) for global documentation and
project-wide contribution guidelines.

---

## Support

- General questions: `info@guardrailapi.com`
- Security disclosures: `security@guardrailapi.com`

For Enterprise support and onboarding, contact:

- `enterprise@guardrailapi.com`

---

© Guardrail Labs LLC 2025. All rights reserved.





# Install — Guardrail Core Runtime

> Guardrail Labs, LLC — Patent Pending  
> This guide covers installation and basic configuration of the
> Guardrail Core Runtime in local, containerized, and early-stage
> production environments.

The Core Runtime is the open-source enforcement engine that evaluates
ingress (prompts) and egress (responses) for LLM traffic. It applies
policy packs, supports clarify-first workflows, and can optionally
integrate with the Guardrail Verifier service.

This document focuses on getting Core running.  
Enterprise deployments use the proprietary Enterprise edition instead.

---

## 1. Requirements

Runtime:

- Linux x86_64
- Python 3.11+ or Docker
- HTTPS egress to your model providers

Recommended dependencies:

- Redis 7+ for idempotency, quotas, rate limiting, and DLQ
- A process manager or container orchestrator for long-running services

---

## 2. Local Development Install

This mode is ideal for development, testing, and early integration work.

### 2.1 Clone the repository

```
git clone https://github.com/guardrail-labs/llm-guardrail-api-next.git

cd llm-guardrail-api-next
```

---

### 2.2 Create a virtual environment and install
```
python -m venv .venv
. .venv/bin/activate
python -m pip install -U pip
pip install -e .[server]
```
---

### 2.3 Run the API with Uvicorn
```
uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8000 --reload
```

Then open:

- `http://127.0.0.1:8000/health`  
- `http://127.0.0.1:8000/docs`

This mode is not hardened and is not intended for production use.

---

## 3. Environment Configuration

Core is configured primarily through environment variables.  
Common examples:

- `GUARDRAIL_ENV` – environment label (for example: `dev`, `staging`, `prod`)
- `REDIS_URL` – Redis instance URL
- `POLICY_PACKS_DIR` – directory containing policy packs
- `LOG_LEVEL` – application log level (for example: `INFO`, `DEBUG`)
- `VERIFIER_URL` – optional URL for the Verifier service

In local setups you can export these manually or use a `.env` file.  
In Docker or Kubernetes, these are typically injected via environment
variables or secrets.

---

## 4. Running Core with Docker

A single-node Docker setup is common for testing or internal services.

From the repository root, ensure a `Dockerfile` is present, then run:

```
docker build -t guardrail-core .
docker run -d
-p 8000:8000
--env GUARDRAIL_ENV=dev
--env REDIS_URL=redis://host.docker.internal:6379/0
guardrail-core
```

Adjust `REDIS_URL` for your environment.  
If you do not have Redis configured, some features (such as idempotency or
rate limiting) may not be available.

Check the service:

- `http://127.0.0.1:8000/health`  
- `http://127.0.0.1:8000/docs`

---

## 5. Policy Packs

Core uses Policy Packs to evaluate requests and responses.

A typical development setup might use a local directory:
```
POLICY_PACKS_DIR=./policy-packs
```


You can mount or point this directory to a checkout of the
`llm-guardrail-policy-packs` repository or to your own internal rule set.

Policy Packs are:

- versioned
- signed (in production workflows)
- loaded at startup
- evaluated on both ingress and egress

Refer to the umbrella documentation and the policy packs repository for
per-pack usage details.

---

## 6. Optional Verifier Integration

If you have the Guardrail Verifier running, you can configure Core to
use it when requests are ambiguous.

Example (environment):

- `VERIFIER_URL=http://verifier:8081`

In this mode:

- Core evaluates the request.
- If intent is unclear, Core calls the Verifier.
- If intent remains unclear, the request is returned to the caller for
  clarification.

The Verifier never executes user content.

---

## 7. Basic Production Considerations

When moving toward production:

- Run behind an API gateway or ingress controller with TLS termination.
- Use a managed or highly available Redis deployment.
- Treat logs and audit events as sensitive.
- Ensure environment configuration is injected securely.
- Use health and readiness checks to integrate with orchestrators.

For environments requiring multi-tenancy, RBAC, data retention, and
evidence bundles, consider the Enterprise edition instead of Core alone.

---

## 8. Troubleshooting

Common checks:

- Verify `REDIS_URL` is reachable if quotas, DLQ, or idempotency are enabled.
- Confirm policy pack paths (`POLICY_PACKS_DIR`) are correct and readable.
- Review application logs for configuration or import errors.
- Use `/health` and `/metrics` to confirm basic service status.

If issues persist, you can open an issue in the Core repository or
contact Guardrail Labs.

---

## 9. Support

For Core Runtime:

- General questions: `info@guardrailapi.com`
- Security disclosures: `security@guardrailapi.com`

For Enterprise deployments or commercial support, contact:

- `enterprise@guardrailapi.com`

---

© Guardrail Labs LLC 2025. All rights reserved.





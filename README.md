[![CI](https://github.com/guardrail-dev/llm-guardrail-api-next/actions/workflows/ci.yml/badge.svg)](https://github.com/guardrail-dev/llm-guardrail-api-next/actions/workflows/ci.yml)
[![Lint: Ruff](https://img.shields.io/badge/lint-ruff-blue)](https://github.com/astral-sh/ruff)
[![Types: mypy](https://img.shields.io/badge/types-mypy-blue)](http://mypy-lang.org/)
[![Tests](https://img.shields.io/badge/tests-pytest-green)](https://docs.pytest.org/)
[![GHCR](https://img.shields.io/badge/image-ghcr.io-informational)](https://github.com/guardrail-dev/llm-guardrail-api-next/pkgs/container/guardrail-core)

# LLM Guardrail Core Runtime

## What's new in v1.4
- **Dual-arm runtime**: ingress & egress guards decoupled, independent failure domains.
- **Sanitizer upgrades**: Unicode normalization, confusables detection, zero-width & ZWJ guards.
- **CI gates**: repo-wide `ruff format`, `ruff check`, `mypy --strict app` now required.

The Guardrail API is the **core runtime** behind the Guardrail firewall. It runs in-band with your
LLM traffic to inspect ingress/egress prompts, enforce policy packs, and emit signed audit events
for downstream observability. This repo contains the enforcement engine, REST API surface, and the
foundational rule execution pipeline. Deployment tooling, dashboards, and admin interfaces live in
the umbrella docs portal referenced below.

## Run it locally
```bash
# install dependencies (includes the API runtime and shared rulepacks)
uv sync  # or: pip install -e .[server]

# boot the ASGI server
uv run python -m app.main

# health probe
curl -s http://localhost:8000/healthz
```

## Docs & references
Full product documentation lives in the Guardrail umbrella portal. Jump directly to:

- [Quickstart](https://docs.guardrail.dev/portal/quickstart)
- [Policy Packs](https://docs.guardrail.dev/portal/policy-packs)
- [Confusables backlog (P1)](https://docs.guardrail.dev/portal/confusables-p1)
- [API reference](https://docs.guardrail.dev/portal/api)

Looking for deployment blueprints, dashboards, or advanced tuning guides? These also live in the
umbrella portal so they stay in sync with the managed platform releases.

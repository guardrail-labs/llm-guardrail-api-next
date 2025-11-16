# LLM Guardrail Core Runtime (v1.5.0)

**Guardrail Labs, LLC — Patent Pending.**  
The Guardrail API is the **core runtime** behind the Guardrail firewall. It runs in-band with your LLM traffic to inspect ingress/egress prompts, enforce policy packs, and emit **HMAC-signed audit events** for observability. This repo contains the enforcement engine, REST API surface, and the foundational rule-execution pipeline. Deployment tooling, dashboards, and admin interfaces live in the **umbrella docs portal** (see links below).

---

## Run it locally

```bash
# Install dependencies (includes API runtime and shared rulepacks)
uv sync           # or: pip install -e .[server]

# Boot the ASGI server
uv run python -m app.main

# Health probe
curl -s http://127.0.0.1:8000/healthz
```

Requires Python 3.11+. We test on 3.11 and 3.12.

## Docs & references

Full product documentation lives in the Guardrail umbrella portal:

https://guardrail-labs.github.io/llm-guardrail-api/

You’ll find:

- Quickstart and local development guides
- Policy pack workflows and examples
- Confusables and Unicode hardening notes (P1 backlog)
- API reference and integration patterns
- Deployment blueprints, dashboards, and advanced tuning guides

## Contributing

Thanks for your interest in contributing! This section explains how to set up a dev environment, run checks locally, and submit changes that pass CI.

### Getting Started

Fork the repo and create a feature branch from main.

Ensure you have Python 3.11+ and either uv (preferred) or pip.

Install dev deps:

```
uv sync
# or:
pip install -e .[dev]
```

Run the API locally:

```
uv run uvicorn app.main:create_app --factory --reload --host 127.0.0.1 --port 8000
curl -s http://127.0.0.1:8000/healthz
```

### Development checks (what CI enforces)

```
# Lint (ruff) and auto-fix trivial issues
python -m ruff check --fix .

# Types (mypy) — uses repo config; tests are excluded
python -m mypy --config-file mypy.ini --strict

# Unit tests
pytest -q

# Optional: security lints
bandit -q -r .
```

### Perf smoke (optional, encouraged before release PRs)

```
uv run python tools/perf/bench.py --smoke --json out-smoke.json
uv run python tools/perf/compare.py --baseline out-baseline.json --candidate out-smoke.json
```

See docs/perf-smoke.md.

### Style & conventions

Python style: enforced by ruff; target line length ≤ 100 chars.

Typing: public functions should be typed; avoid ambiguous lambdas where mypy struggles.

Security: don’t use assert for request validation; return explicit 4xx/5xx.

Commits/PRs: keep changes scoped; include “What / Why / Risk / Verify” in PR descriptions.

## CI & audits

CI runs lint, type-checks, tests, and non-blocking repo audits.

gitleaks and trufflehog findings are preserved as artifacts.

GitHub Actions pinning audit produces unpinned-actions.{md,json}.

See docs/repo-audits.md.

## Enforcement posture (for contributors)

The API enforces configured policies in-band around model I/O. When policies are active, disallowed outputs are intercepted and mitigated (block / clarify / redact) before returning to the client. Administrators must enable/maintain the appropriate packs.

Read more in docs/security-model.md.

## Enterprise tests (opt-in)

Enterprise tests are gated and do not run on public CI by default.

Local:

```
pip install fastapi pyyaml
pytest -m enterprise --run-enterprise
```

CI runs on a self-hosted runner/image when labeled or manually dispatched.
See docs/enterprise-tests.md.

## Releases

Maintainer steps live in:

RELEASING.md → points to docs/release-checklist.md

Draft notes stub: docs/release-notes-stub-rc1.md

This repository currently uses manual tags (e.g., v1.4.0) to publish artifacts. If release automation is re-enabled later, this README will be updated.

## Reporting security issues

Please do not open public issues for vulnerabilities. Use GitHub Security Advisories or follow the process in SECURITY.md.

## License

Apache-2.0. See LICENSE.

© Guardrail Labs, LLC. All rights reserved. Patent pending.

<!-- Badges -->
![version](https://img.shields.io/badge/version-v1.4.0--rc1-blue)
![python](https://img.shields.io/badge/python-3.11%20%7C%203.12-3776ab)
![tests](https://img.shields.io/badge/tests-passing-brightgreen)
![coverage](https://img.shields.io/badge/coverage-%E2%89%A585%25-brightgreen)

# Guardrail API — Core Runtime

## What is this?
Guardrail Core is the public runtime that sits between clients and models to:
- Sanitize inputs (unicode/confusables/hidden text) **before** policy evaluation.
- Enforce policies with a **clarify-first, then block** approach.
- Keep **ingress** and **egress** enforcement **independent** to avoid single points of failure.

## Clarify-First Policy
Ambiguous intent → return `202` with `{ "clarify": true }`, never executing unverified requests.

```mermaid
flowchart LR
A[Request In] --> B[Sanitizer (unicode/confusables)]
B --> C[Ingress Policy]
C -- allow --> D[Model Call]
C -- clarify --> E[202 Clarify]
C -- block_input_only/deny/lock --> F[400 Blocked]
D --> G[Egress Policy]
G -- allow --> H[Response Out]
G -- block/lock --> I[400 Blocked]
```

## Dual-Arm Isolation (Ingress/Egress)
Ingress and egress run independently. A failure or block in one arm does not disable the other. This eliminates single-point-of-failure risks and preserves output-guarding even if ingress is degraded.

## Unicode/Confusables Sanitizer (Default-On)
Normalizes unicode, strips zero-widths, detects confusables.

Runs before policy evaluation.

Sanitized text is applied back into structured payloads (without dropping metadata).

## Quick Start (FastAPI)
```python
from fastapi import FastAPI
from app.runtime.router import router as core_router

app = FastAPI()
app.include_router(core_router, prefix="")  # /chat/completions
```

Run:

```bash
uvicorn app.main:app --reload
```

## Policy Actions & Router Semantics
- Ingress actions that block model calls: `deny`, `block`, `lock`, `block_input_only`
- Clarify: `clarify` → HTTP 202 with `{ "clarify": true }`
- Egress runs even if ingress allowed, guarding outbound content.

## CI & Quality Gates
- `ruff format --check .` and `ruff check .`
- `mypy --strict app`
- `pytest --cov=app --cov-report=term-missing --maxfail=1 --quiet` with `--cov-fail-under=85`

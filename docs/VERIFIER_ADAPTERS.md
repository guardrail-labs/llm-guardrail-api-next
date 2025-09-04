# Verifier Adapters — Production Contract

**Goal:** A pluggable, provider-agnostic adapter layer that classifies requests as  
**"safe" | "unsafe" | "unclear"** without leaking user data or blocking the request path.

This document defines the **interface**, **request/response mapping**, **timeouts/retries**, and **observability** for production adapters (OpenAI, Anthropic, Azure). It also specifies environment configuration and test/mocking guidance.

---

## 1) Responsibilities

- Accept a normalized **ingress payload** (text + metadata + optional artifacts).
- Call the provider’s moderation/verifier endpoint(s) with **privacy constraints** (minimize data; prefer hashes/summaries).
- Return a single string verdict: `"safe" | "unsafe" | "unclear"`.
- NEVER perform blocking I/O on the main thread; enforce timeouts.
- Fail **closed-to-unclear** (never throw through request path).

---

## 2) Interface (Python)

The public interface is `VerifierAdapter`:

```python
from typing import Literal, Protocol, Mapping, Any

Verdict = Literal["safe", "unsafe", "unclear"]

class VerifierAdapter(Protocol):
    def assess(self, payload: Mapping[str, Any]) -> Verdict: ...
```

Input (payload): a normalized dict (see §3) assembled from the request (prompt, file kinds, debug flags).

Output: one of the three literals. No exceptions; handle errors internally.

A minimal, typed base and examples live in app/services/verifier/adapters/ (see file list below).

## 3) Normalized Request Shape (what we send)

Adapters receive redacted summaries, not raw user content when possible.

```
{
  "prompt_text": "string (possibly redacted/summarized)",
  "modalities": ["text","pdf","docx","image","audio","video"],
  "policy_context": {
    "pii_ruleset": "default|hipaa|ferpa|custom",
    "block_mode": "baseline",
    "override_mode": "clarify"
  },
  "ingress_flags": ["opaque_media_noninterpretable"],
  "debug": {
    "sources": [
      {"type":"pdf","rule_hits":["pdf:hidden"],"meta":{"spans_count":2}},
      {"type":"docx","rule_hits":["inj:override_safety"],"meta":{"lines_scanned":7}}
    ]
  }
}
```

Notes

If the provider requires snippets, send small excerpts or hashes where feasible.

For images, only pass the flag (opaque) and basic stats; do not upload bytes from this path.

## 4) Verdict Mapping

Provider → our verdict:

| Provider signal | Verdict |
| --- | --- |
| Explicit block / policy_violation / high risk | unsafe |
| Clean / allow | safe |
| Low-confidence / model refused / timeout / error | unclear |

We never pass exceptions outward. Timeouts & non-200s return unclear and log a structured warning.

## 5) Timeouts, Retries, Circuit

Timeout: VERIFIER_TIMEOUT_MS (default 1500ms)

Retries: VERIFIER_MAX_RETRIES (default 1, only on network timeouts/5xx)

Circuit breaker: trip to open after 5 consecutive failures; remain open for VERIFIER_CIRCUIT_OPEN_SEC (default 60s) returning unclear immediately.

Rationale: verifier is a scoring augmentation; the request path must remain responsive.

## 6) Security & Privacy

Never log raw prompts or files. Logs contain hashes + rule IDs only.

Strip API keys from outbound payloads; use authorization headers only.

Respect data residency if required (Azure regions, etc.).

Support per-tenant keys via env or secret manager integration.

## 7) Observability

Emit counters and timings (pseudocode; actual metrics module TBD):

```
verifier.requests_total{provider, outcome}

verifier.latency_ms{provider} (histogram)

verifier.errors_total{provider, reason}
```

When unsafe, the Abuse Gate will call record_unsafe and attach:

X-Guardrail-Decision, X-Guardrail-Mode (if escalated), X-Guardrail-Incident-ID.

## 8) Providers (intended mappings)
### OpenAI

Endpoint: Moderation / reasoner endpoint depending on model selection.

Env:

OPENAI_API_KEY

OPENAI_VERIFIER_MODEL (e.g., omni-moderation-latest or policy-tuned)

VERIFIER_TIMEOUT_MS, VERIFIER_MAX_RETRIES, VERIFIER_CIRCUIT_OPEN_SEC

### Anthropic

Endpoint: Safety/Content moderation via Messages with a compact prompt.

Env:

ANTHROPIC_API_KEY

ANTHROPIC_VERIFIER_MODEL

Shared timeout/retries/circuit envs

### Azure OpenAI

Endpoint: Azure AOAI deployment

Env:

AZURE_OPENAI_API_KEY

AZURE_OPENAI_ENDPOINT

AZURE_OPENAI_DEPLOYMENT (verifier deployment name)

Shared timeout/retries/circuit envs

Note: Choose one active adapter via VERIFIER_ADAPTER env: none|openai|anthropic|azure.

## 9) Local Development & Tests

Unit tests monkeypatch the adapter and do not make network calls.

CI uses LocalRuleAdapter (baseline pattern rules, deterministic).

Contract tests assert:

- Returns only safe|unsafe|unclear
- Timeouts → unclear
- Error handling increments error metric; no exceptions raised.

## 10) Wiring (non-blocking, optional)

At runtime, abuse_gate.fetch_verdict(request) can resolve an adapter singleton:

```python
# app/middleware/abuse_gate.py (sketch)
from app.services.verifier.adapters.base import resolve_adapter_from_env

_adapter = resolve_adapter_from_env()  # returns LocalRuleAdapter if VERIFIER_ADAPTER=none

def fetch_verdict(request: Request) -> str:
    # Extract normalized payload from request (body + debug flags)
    payload = {"prompt_text": "...", "modalities": ["text"], "debug": {"sources": []}}
    try:
        return _adapter.assess(payload)
    except Exception:
        return "unclear"
```

(We keep this disabled in CI until you approve a wiring PR.)

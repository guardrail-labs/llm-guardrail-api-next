# Policy Packs v1 (Overview)

**Purpose.** Provide auditable, toggleable rules that map common text patterns and
keywords to advisory actions (`pass|flag|clarify|block`) for compliance and safety.

## Packs
- **HIPAA**: PHI indicators (SSN, email, phone) with advisory actions.
- **GDPR**: Personal data and health-related terms as special-category signals.
- **CALIFORNIA**: Safety/disclosure signals (high-risk instruction phrasing) and
  basic privacy indicators.

> These packs are illustrative, not legal advice. Integrators should review and
> tailor to their obligations.

## Schema
Each `*.yaml` file defines:
- `pack`: identifier (e.g., `HIPAA`).
- `version`: pack version string.
- `rules[]`: array of rules:
  - `id`: unique within pack.
  - `title`: human-readable summary.
  - `severity`: `low|medium|high`.
  - `advisory`: `pass|flag|clarify|block` (non-binding in v1).
  - `pattern`: optional regex (case-insensitive).
  - `any_terms[]`: optional keywords list (case-insensitive).
  - `references[]`: citations or legal anchors.

## Headers
When violations are found:


X-Guardrail-Policy: <PACK>:<rule_id>[,<PACK>:<rule_id>...];action=<advisory>

This is **advisory**. Enforcement occurs elsewhere (e.g., decision engine) and
can escalate per tenant.


How to surface headers (example usage)
(Optional example for you; no changes required to existing code paths.)

from app.policy.packs import load_packs
from app.policy.pack_engine import evaluate_text, policy_headers

packs = load_packs()
violations, action = evaluate_text(output_text, packs)
hdrs = policy_headers(violations, action)
# Attach hdrs to response; your decision engine can act on `action`.


Local run

ruff check .
mypy .
pytest -q

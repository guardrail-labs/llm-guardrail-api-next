# Bindings Validation & Conflicts

The API now includes a stdlib validator for **bindings** (tenant/bot → policy).

- Wildcards: `*` for tenant and/or bot.
- Priority: higher `priority` wins when multiple bindings overlap.
- Conflicts:
  - **duplicate** (warning): same target, same outcome – remove one
  - **incompatible** (error): same target, different outcome – must fix
  - **overlap** (warning): wildcard overlap with equal priorities – ambiguous
  - **shadowed** (info): lower priority overlapped by higher – FYI only

Code:
- `app/services/bindings/models.py`
- `app/services/bindings/validator.py`
- Optional audit wrappers: `app/services/bindings/audit.py`

Example (admin dry-run):

```py
from app.services.bindings.models import Binding
from app.services.bindings.validator import validate_bindings, choose_binding_for

bindings = [
    Binding(tenant_id="*", bot_id="b1", policy_version="finance", priority=1),
    Binding(tenant_id="acme", bot_id="b1", policy_version="finance-strict", priority=5),
]
issues = validate_bindings(bindings)
selected, candidates = choose_binding_for(bindings, "acme", "b1")
```

To record issues to the audit pipeline:

```py
from app.services.bindings.audit import record_validation_results
record_validation_results(issues)
```

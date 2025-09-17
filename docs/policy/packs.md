# Policy Packs (Scaffold)

Policy Packs let you compose Guardrail policy from small YAML modules (for example, `base`, `hipaa`, `gdpr`). Packs are merged **in order**; later packs override earlier ones and can append rules.

> This scaffold introduces packs and the loader only. Wiring into the live policy happens in a follow-up change.

## Pack location

```
policies/packs/
├── base.yaml
├── hipaa.yaml
└── gdpr.yaml
```

## Pack schema (flexible)

```yaml
meta:
  name: <string>
  version: <int>
  tags: [ ... ]
settings:
  # arbitrary nested keys (merged deeply)
rules:
  deny: []        # list; appended
  allow: []       # list; appended
  redact: []      # list; appended
  verifiers: []   # list; appended
```

## Loader API

```python
from app.services.policy_packs import merge_packs

policy, version, refs = merge_packs(["base", "hipaa", "gdpr"])
print(version)  # sha256 over name+raw bytes in order
```

- Merge rules: dictionaries recursively overlay, lists concatenate, and scalars override.
- Versioning: any change to pack content or ordering changes the version hash.

## Next (wiring in runtime)

A follow-up will:

- Add a configuration key `policy_packs = ["base", ...]`.
- Replace the current policy load with `merge_packs(...)`.
- Expose `current_rules_version()` derived from the merged packs' version.

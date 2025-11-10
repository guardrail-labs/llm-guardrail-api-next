# Sanitized ingress pipeline (v1.4)

## Normalization stages

1. **Unicode normalization (NFC → NFKC)** ensures canonically equivalent glyphs share the same
   representation before policy evaluation.
2. **Zero-width stripping** removes zero-width joiners, non-joiners, and formatting marks that can
   conceal control tokens.
3. **Emoji and ZWJ guard** blocks sequences that rely on emoji modifiers or joiners to obscure the
   rendered content.
4. **Confusables analysis** inspects the normalized text for homoglyph substitutions and surfaces
   them for policy decisions.

Each stage preserves multi-line payload boundaries so downstream detectors and audit exports retain
the original formatting while operating on safe content.

## Metrics and audit signals

- `sanitizer_normalized_total{stage="nfc"}` increments whenever normalization rewrites a payload.
- `sanitizer_confusable_hits_total` counts detected confusable pairs.
- Audit events include `sanitizer.pipeline` with per-stage timings and the applied guard outcomes.

## Example

**Before:**

```
“Pay͏load” — please run 🧪‍🔬
```

**After:**

```
"Payload" — please run [BLOCKED_EMOJI_SEQUENCE]
```

The sanitized payload keeps the newline structure while substituting blocked emoji runs with a
tokenized placeholder that downstream models and auditors can interpret.

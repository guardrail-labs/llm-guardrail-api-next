# Dual-Arm Isolation

- Ingress: sanitize → evaluate → may clarify or block *before* any model call.
- Egress: evaluate model output independently; can block or redact even if ingress allowed.
- Failure isolation: an error in one arm does not disable the other arm’s protection.

# Audit HMAC secret rotation (dual-secret)

## Receiver
Set both env vars during rotate window:
- `AUDIT_RECEIVER_SIGNING_SECRET=<new-primary>`
- `AUDIT_RECEIVER_SIGNING_SECRET_SECONDARY=<old-primary>`

Receiver accepts signatures produced by either secret.

## Forwarder
Flip the forwarder to use the new secret:
- `AUDIT_FORWARD_SIGNING_SECRET=<new-primary>`

After traffic is stable for 24–48h, remove the secondary on receiver.

## Notes
- Timestamp freshness (`AUDIT_RECEIVER_ENFORCE_TS=1`) requires `X-Signature-Ts`.
- Signature formula: HMAC-SHA256 over `"<ts>.<json-bytes>"` (uncompressed).


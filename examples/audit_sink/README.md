# Audit sink example

Run this FastAPI app to receive audit events.

## Point your forwarder at it

**Signature scheme:**  
`X-Signature = "sha256=" + HMAC_SHA256(AUDIT_FORWARD_SIGNING_SECRET, f"{X-Signature-Ts}.{raw_json_body}")`  
If you set `AUDIT_RECEIVER_ENFORCE_TS=1`, the receiver *requires* `X-Signature-Ts` and rejects stale timestamps beyond `AUDIT_RECEIVER_TS_SKEW_SEC`.


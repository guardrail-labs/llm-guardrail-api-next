# Audit payload compression (gzip)

## Forwarder
Enable compression:


AUDIT_FORWARD_COMPRESS=1

The forwarder sends `Content-Encoding: gzip` and signs the **uncompressed** JSON.

## Receiver
The receiver auto-detects `Content-Encoding: gzip`, decompresses,
then verifies the signature over `"<ts>.<json-bytes>"`.

## Smoke


FORWARD_URL=https://.../audit
 FORWARD_KEY=... HMAC_SECRET=... USE_GZIP=1
bash scripts/audit/prod_smoke.sh


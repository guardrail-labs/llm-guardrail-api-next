# Webhooks — Signature Verification (HMAC-SHA256)

Guardrail signs every webhook using HMAC-SHA256 with your configured `webhook_secret`.

## Signing modes

- **v0 (default)** — `webhook_signing_mode=body`  
  - Header: `X-Guardrail-Signature: sha256=<hex>`  
  - HMAC over **raw body only**.
- **v1 (optional)** — `webhook_signing_mode=ts_body`  
  - Headers:
    - `X-Guardrail-Timestamp: <unix seconds>`
    - `X-Guardrail-Signature-V1: sha256=<hex>`
  - HMAC over `f"{timestamp}\n{raw_body}"`.
  - If `webhook_signing_dual=true` (default), **both** v0 and v1 headers are sent for migration.

### Receiver verification strategy

- Prefer v1 if both are present (validate timestamp freshness ±5m, then HMAC).  
- Otherwise fall back to v0.  
- Reject requests without a recognizable signature header.

Example flow:

```python
if sig_v1 and ts:
    verify_v1(ts, sig_v1, body)
elif sig_v0:
    verify_v0(sig_v0, body)
else:
    raise HTTPException(401, "missing signature")
```

## Verification Steps

1. Read the raw request body as bytes.
2. Check for `X-Guardrail-Signature-V1` (and the matching `X-Guardrail-Timestamp`).
   - Split the header on `=` and ensure the algorithm is `sha256`.
   - Parse the timestamp as integer seconds and ensure `abs(now - ts) <= 300` (or your policy).
   - Compute `expected = hex(hmac_sha256(secret, f"{ts}\n{raw_body}"))`.
   - Compare the lowercase hex digest using **constant-time** equality.
3. If v1 headers are absent, read `X-Guardrail-Signature`, enforce the `sha256` prefix, compute `expected = hex(hmac_sha256(secret, raw_body))`, and compare using **constant-time** equality.
4. Reject if no signature matches.

---

## Python (FastAPI) Example

```python
from fastapi import FastAPI, Request, HTTPException
import hmac, hashlib, time

app = FastAPI()
WEBHOOK_SECRET = b"replace-with-your-secret"


def _parse_signature(header: str) -> str:
    try:
        algo, provided = header.split("=", 1)
    except ValueError:
        raise HTTPException(400, "bad signature header")
    if algo.lower() != "sha256":
        raise HTTPException(400, "unsupported algo")
    return provided.strip()


@app.post("/hook")
async def hook(request: Request):
    raw = await request.body()
    sig_v1 = request.headers.get("X-Guardrail-Signature-V1")
    sig_v0 = request.headers.get("X-Guardrail-Signature")
    ts = request.headers.get("X-Guardrail-Timestamp")

    if sig_v1 and ts:
        try:
            ts_i = int(ts)
        except ValueError:
            raise HTTPException(400, "bad timestamp")
        if abs(int(time.time()) - ts_i) > 300:
            raise HTTPException(401, "stale timestamp")

        provided = _parse_signature(sig_v1).lower()
        preimage = f"{ts}\n".encode("utf-8") + raw
        expected = hmac.new(WEBHOOK_SECRET, preimage, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, provided):
            raise HTTPException(401, "invalid signature")
        return {"ok": True}

    if not sig_v0:
        raise HTTPException(401, "missing signature")

    provided = _parse_signature(sig_v0).lower()
    expected = hmac.new(WEBHOOK_SECRET, raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, provided):
        raise HTTPException(401, "invalid signature")

    return {"ok": True}
```

## Node.js (Express) Example

```javascript
const express = require("express");
const crypto = require("crypto");
const app = express();
app.use(express.raw({ type: "*/*" }));

const WEBHOOK_SECRET = Buffer.from("replace-with-your-secret", "utf8");

function constEq(a, b) {
  const A = Buffer.from(a, "utf8");
  const B = Buffer.from(b, "utf8");
  if (A.length !== B.length) return false;
  return crypto.timingSafeEqual(A, B);
}

function parseSignature(header) {
  const [algo, provided] = (header || "").split("=");
  if ((algo || "").toLowerCase() !== "sha256" || !provided) {
    return null;
  }
  return provided.trim().toLowerCase();
}

app.post("/hook", (req, res) => {
  const sigV1 = req.header("X-Guardrail-Signature-V1");
  const sigV0 = req.header("X-Guardrail-Signature");
  const ts = req.header("X-Guardrail-Timestamp");

  if (sigV1 && ts) {
    const tsInt = Number.parseInt(ts, 10);
    if (!Number.isFinite(tsInt)) return res.status(400).send("bad timestamp");
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - tsInt) > 300) return res.status(401).send("stale timestamp");

    const provided = parseSignature(sigV1);
    if (!provided) return res.status(400).send("bad signature header");

    const preimage = Buffer.concat([Buffer.from(`${ts}\n`, "utf8"), req.body]);
    const expected = crypto
      .createHmac("sha256", WEBHOOK_SECRET)
      .update(preimage)
      .digest("hex");

    if (!constEq(expected, provided)) return res.status(401).send("invalid signature");
    return res.json({ ok: true });
  }

  if (!sigV0) return res.status(401).send("missing signature");

  const provided = parseSignature(sigV0);
  if (!provided) return res.status(400).send("bad signature header");

  const expected = crypto.createHmac("sha256", WEBHOOK_SECRET)
    .update(req.body)
    .digest("hex");

  if (!constEq(expected, provided)) return res.status(401).send("invalid signature");
  res.json({ ok: true });
});

app.listen(3000);
```

## Go (net/http) Example

```go
package main

import (
  "crypto/hmac"
  "crypto/sha256"
  "encoding/hex"
  "io"
  "net/http"
  "strconv"
  "strings"
  "time"
)

var secret = []byte("replace-with-your-secret")

func constEq(a, b string) bool {
  if len(a) != len(b) { return false }
  var v byte
  for i := range a { v |= a[i] ^ b[i] }
  return v == 0
}

func parseSignature(header string) (string, bool) {
  parts := strings.SplitN(header, "=", 2)
  if len(parts) != 2 || strings.ToLower(parts[0]) != "sha256" {
    return "", false
  }
  return strings.ToLower(strings.TrimSpace(parts[1])), true
}

func hook(w http.ResponseWriter, r *http.Request) {
  body, _ := io.ReadAll(r.Body)
  sigV1 := r.Header.Get("X-Guardrail-Signature-V1")
  sigV0 := r.Header.Get("X-Guardrail-Signature")
  ts := r.Header.Get("X-Guardrail-Timestamp")

  if sigV1 != "" && ts != "" {
    tsI, err := strconv.ParseInt(ts, 10, 64)
    if err != nil { http.Error(w, "bad timestamp", 400); return }
    if abs(time.Now().Unix()-tsI) > 300 { http.Error(w, "stale timestamp", 401); return }

    provided, ok := parseSignature(sigV1)
    if !ok { http.Error(w, "bad signature header", 400); return }

    preimage := append([]byte(ts+"\n"), body...)
    mac := hmac.New(sha256.New, secret)
    mac.Write(preimage)
    expected := hex.EncodeToString(mac.Sum(nil))

    if !constEq(expected, provided) { http.Error(w, "invalid signature", 401); return }
    w.Write([]byte(`{"ok":true}`))
    return
  }

  if sigV0 == "" { http.Error(w, "missing signature", 401); return }

  provided, ok := parseSignature(sigV0)
  if !ok { http.Error(w, "bad signature header", 400); return }

  mac := hmac.New(sha256.New, secret)
  mac.Write(body)
  expected := hex.EncodeToString(mac.Sum(nil))
  if !constEq(expected, provided) { http.Error(w, "invalid signature", 401); return }
  w.Write([]byte(`{"ok":true}`))
}

func abs(x int64) int64 { if x < 0 { return -x }; return x }

func main() { http.HandleFunc("/hook", hook); http.ListenAndServe(":8080", nil) }
```

## Bash (ad-hoc verify)

```bash
# usage: verify.sh <secret> <body-file> <signature-header> [timestamp]
secret="$1"; body="$2"; signature="$3"; ts="$4"
algo="${signature%%=*}"; provided="${signature#*=}"
if [ "${algo,,}" != "sha256" ]; then echo "unsupported algo"; exit 1; fi
provided_lower="$(printf "%s" "$provided" | tr 'A-F' 'a-f')"

if [ -n "$ts" ]; then
  expected="$({ printf '%s\n' "$ts"; cat "$body"; } | openssl dgst -sha256 -hmac "$secret" -binary | xxd -p -c 256)"
else
  expected="$(cat "$body" | openssl dgst -sha256 -hmac "$secret" -binary | xxd -p -c 256)"
fi
[ "$expected" = "$provided_lower" ] && echo "OK" || echo "BAD"
```

## Operational Tips

- Rotate `webhook_secret` with overlap: accept either of two secrets for a short window.
- Ensure idempotency on the receiver; Guardrail can retry deliveries.
- Monitor `guardrail_webhook_deliveries_total{outcome, status}` and latency histograms.
- Toggle `webhook_signing_mode=ts_body` (optionally with `webhook_signing_dual=false`) when your receivers accept the v1 headers.

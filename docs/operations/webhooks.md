# Webhooks — Signature Verification (HMAC-SHA256)

Guardrail signs every webhook using HMAC-SHA256 with your configured `webhook_secret`.

## Headers

- `X-Guardrail-Signature`: `sha256=<hex digest>`
- `X-Guardrail-Timestamp`: Unix epoch seconds (optional but recommended)

## Signing Payload

- **Preferred (timestamped)**: the HMAC is computed over:
  ```text
  preimage = f"{timestamp}\n{raw_body}"
  ```
- **Minimal (legacy)**: if `X-Guardrail-Timestamp` is missing, the HMAC is computed over the **raw body** only.

> **Important:** Always verify against the **raw** request body bytes as received on the wire (no JSON re-serialization). Reject if the timestamp is too old (e.g., > 5 minutes) to prevent replay.

## Verification Steps

1. Read `X-Guardrail-Signature` and (optionally) `X-Guardrail-Timestamp`.
2. Build `preimage` as above (timestamped if header present, else raw body).
3. Compute `expected = hex(hmac_sha256(secret, preimage))` (lowercase hex).
4. Compare with the header using **constant-time** equality.
5. If timestamp is present, ensure `abs(now - ts) <= 300` seconds.

---

## Python (FastAPI) Example

```python
from fastapi import FastAPI, Request, HTTPException
import hmac, hashlib, time

app = FastAPI()
WEBHOOK_SECRET = b"replace-with-your-secret"

def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)

@app.post("/hook")
async def hook(request: Request):
    raw = await request.body()
    sig = request.headers.get("X-Guardrail-Signature", "")
    ts = request.headers.get("X-Guardrail-Timestamp")

    # extract provided hex from "sha256=<hex>"
    try:
        algo, provided = sig.split("=", 1)
    except ValueError:
        raise HTTPException(400, "bad signature header")

    if algo.lower() != "sha256":
        raise HTTPException(400, "unsupported algo")

    if ts:
        try:
            ts_i = int(ts)
        except ValueError:
            raise HTTPException(400, "bad timestamp")
        if abs(int(time.time()) - ts_i) > 300:
            raise HTTPException(401, "stale timestamp")
        preimage = f"{ts_i}\n".encode() + raw
    else:
        preimage = raw

    expected = hmac.new(WEBHOOK_SECRET, preimage, hashlib.sha256).hexdigest()
    if not constant_time_eq(expected, provided.lower()):
        raise HTTPException(401, "invalid signature")

    # ✔ verified — process event
    return {"ok": True}
```

## Node.js (Express) Example

```javascript
const express = require("express");
const crypto = require("crypto");
const app = express();

// Important: capture raw body
app.use(express.raw({ type: "*/*" }));
const WEBHOOK_SECRET = Buffer.from("replace-with-your-secret", "utf8");

function constEq(a, b) {
  const ba = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

app.post("/hook", (req, res) => {
  const sig = req.header("X-Guardrail-Signature") || "";
  const ts = req.header("X-Guardrail-Timestamp");
  const [algo, provided] = sig.split("=");
  if ((algo || "").toLowerCase() !== "sha256") {
    return res.status(400).send("unsupported algo");
  }

  let preimage;
  if (ts) {
    const tsInt = parseInt(ts, 10);
    if (!Number.isFinite(tsInt)) return res.status(400).send("bad timestamp");
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - tsInt) > 300) return res.status(401).send("stale timestamp");
    preimage = Buffer.concat([Buffer.from(String(tsInt) + "\n"), req.body]);
  } else {
    preimage = req.body;
  }

  const expected = crypto.createHmac("sha256", WEBHOOK_SECRET)
    .update(preimage)
    .digest("hex");

  if (!constEq(expected, (provided || "").toLowerCase())) {
    return res.status(401).send("invalid signature");
  }
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

func hook(w http.ResponseWriter, r *http.Request) {
  body, _ := io.ReadAll(r.Body)
  sig := r.Header.Get("X-Guardrail-Signature")
  ts := r.Header.Get("X-Guardrail-Timestamp")
  parts := strings.SplitN(sig, "=", 2)
  if len(parts) != 2 || strings.ToLower(parts[0]) != "sha256" {
    http.Error(w, "bad signature header", 400); return
  }
  var preimage []byte
  if ts != "" {
    tsI, err := strconv.ParseInt(ts, 10, 64)
    if err != nil { http.Error(w, "bad timestamp", 400); return }
    if abs(time.Now().Unix()-tsI) > 300 { http.Error(w, "stale timestamp", 401); return }
    preimage = append([]byte(ts+"\n"), body...)
  } else {
    preimage = body
  }
  mac := hmac.New(sha256.New, secret)
  mac.Write(preimage)
  expected := hex.EncodeToString(mac.Sum(nil))
  if !constEq(expected, strings.ToLower(parts[1])) {
    http.Error(w, "invalid signature", 401); return
  }
  w.Write([]byte(`{"ok":true}`))
}

func abs(x int64) int64 { if x < 0 { return -x }; return x }

func main() { http.HandleFunc("/hook", hook); http.ListenAndServe(":8080", nil) }
```

## Bash (ad-hoc verify)

```bash
# usage: verify.sh <secret> <timestamp-or-empty> <body-file> <provided-hex>
secret="$1"; ts="$2"; body="$3"; provided="$4"
if [ -n "$ts" ]; then preimage="$(printf "%s\n" "$ts")$(cat "$body")"; else preimage="$(cat "$body")"; fi
expected="$(printf "%s" "$preimage" | openssl dgst -sha256 -hmac "$secret" -binary | xxd -p -c 256)"
[ "$expected" = "$(printf "%s" "$provided" | tr 'A-F' 'a-f')" ] && echo "OK" || echo "BAD"
```

## Operational Tips

- Rotate `webhook_secret` with overlap: accept either of two secrets for a short window.
- Ensure idempotency on the receiver; Guardrail can retry deliveries.
- Monitor `guardrail_webhook_deliveries_total{outcome, status}` and latency histograms.

# Webhooks — Signature Verification (HMAC-SHA256)

Guardrail signs every webhook using HMAC-SHA256 with your configured `webhook_secret`.

## Headers

- `X-Guardrail-Signature`: `sha256=<hex digest>`
- `X-Guardrail-Timestamp`: Unix epoch seconds (optional; for replay protection only)

## Signing Payload (current behavior)

- **Signature input:** the **raw request body bytes** only.
- **Timestamp:** if present, validate staleness (e.g., ±5 minutes), but **do not** include it in the HMAC.

> **Why:** This matches the current sender. A future “v1” scheme may include the timestamp in the HMAC with a versioned header; when that ships, we’ll document a dual-accept period.

## Verification Steps

1. Read `X-Guardrail-Signature` and (optionally) `X-Guardrail-Timestamp`.
2. Compute `expected = hex(hmac_sha256(secret, raw_body))` (lowercase hex).
3. Compare with the header using **constant-time** equality against the lowercase digest.
4. If `X-Guardrail-Timestamp` is present, ensure `abs(now - ts) <= 300` seconds (or your policy).

---

## Python (FastAPI) Example

```python
from fastapi import FastAPI, Request, HTTPException
import hmac, hashlib, time

app = FastAPI()
WEBHOOK_SECRET = b"replace-with-your-secret"

@app.post("/hook")
async def hook(request: Request):
    raw = await request.body()

    sig = request.headers.get("X-Guardrail-Signature", "")
    ts = request.headers.get("X-Guardrail-Timestamp")

    # optional anti-replay
    if ts:
        try:
            ts_i = int(ts)
        except ValueError:
            raise HTTPException(400, "bad timestamp")
        if abs(int(time.time()) - ts_i) > 300:
            raise HTTPException(401, "stale timestamp")

    try:
        algo, provided = sig.split("=", 1)
    except ValueError:
        raise HTTPException(400, "bad signature header")
    if algo.lower() != "sha256":
        raise HTTPException(400, "unsupported algo")

    expected = hmac.new(WEBHOOK_SECRET, raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, provided.lower()):
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

app.post("/hook", (req, res) => {
  const sig = req.header("X-Guardrail-Signature") || "";
  const ts = req.header("X-Guardrail-Timestamp");

  if (ts) {
    const tsInt = parseInt(ts, 10);
    if (!Number.isFinite(tsInt)) return res.status(400).send("bad timestamp");
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - tsInt) > 300) return res.status(401).send("stale timestamp");
  }

  const [algo, provided] = sig.split("=");
  if ((algo || "").toLowerCase() !== "sha256") {
    return res.status(400).send("unsupported algo");
  }

  const expected = crypto.createHmac("sha256", WEBHOOK_SECRET)
    .update(req.body)
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

  if ts != "" {
    tsI, err := strconv.ParseInt(ts, 10, 64)
    if err != nil { http.Error(w, "bad timestamp", 400); return }
    if abs(time.Now().Unix()-tsI) > 300 { http.Error(w, "stale timestamp", 401); return }
  }

  parts := strings.SplitN(sig, "=", 2)
  if len(parts) != 2 || strings.ToLower(parts[0]) != "sha256" {
    http.Error(w, "bad signature header", 400); return
  }

  mac := hmac.New(sha256.New, secret)
  mac.Write(body)
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
# usage: verify.sh <secret> <body-file> <provided-hex>
secret="$1"; body="$2"; provided="$3"
expected="$(cat "$body" | openssl dgst -sha256 -hmac "$secret" -binary | xxd -p -c 256)"
[ "$expected" = "$(printf "%s" "$provided" | tr 'A-F' 'a-f')" ] && echo "OK" || echo "BAD"
```

## Operational Tips

- Rotate `webhook_secret` with overlap: accept either of two secrets for a short window.
- Ensure idempotency on the receiver; Guardrail can retry deliveries.
- Monitor `guardrail_webhook_deliveries_total{outcome, status}` and latency histograms.

Migration note (future): when we introduce versioned signing (timestamp included), docs will add a v1 section and a dual-accept window.

# Idempotency: Client Guidance (keys & conflicts)

Audience: client teams and SDK authors.

## TL;DR

- Send **`X-Idempotency-Key`** on **POST/PUT/PATCH** retries for the *same logical
  operation*.
- Key **charset**: `A–Z a–z 0–9 - _` only. **Length:** 1..200.
- Prefer a **client-generated operation ID** (UUIDv4, ULID) per logical operation.
- Do **not** embed PII in keys. Use opaque, non-guessable tokens.
- If the request changes in any way, **use a new key** to avoid conflicts.
- Detect replays via response header **`idempotency-replayed: true|false`**.

---

## Why keys matter

Keys prevent duplicate side effects when clients retry on timeouts/network errors.
The server stores the leader’s response for a short window; followers reuse it.

Server signals you may see:
- `idempotency-replayed: true|false` (response header)
- `idempotency-replay-count: N` (response header, optional)
- `X-Idempotency-Key: <key>` (echoed on replay)

> Notes:
> - Streaming responses are not cached unless explicitly enabled server-side.
> - Very large bodies may not be cached server-side; a later retry might re-execute.

---

## What to put in the key

Use **one** of the following patterns:

### 1) Operation ID (recommended for POST creates)

- Generate once, persist with the client’s operation record.
- Reuse **exactly** on retries; change the key for any new attempt.

Examples (valid charset):
- `c01f7a4a0e8743a2a8dc1e8e5a60f658` (hex UUID w/o dashes)
- `01J9Z9W9J7P8CDQ8R32Q3V9R2M` (ULID base32 w/o padding)
- `order-req_20241002_5L0GJYJ9`

Avoid:
- Base64 with `+` `/` `=` (not allowed by charset).
- Email, names, or order details (PII).

### 2) Deterministic key from request (advanced)

If you must derive from content, hash a **canonical form**:

```
key = hex( SHA256(
METHOD + "\n" +
PATH_TEMPLATE + "\n" + # e.g., /v1/orders (no path params)
TENANT_ID + "\n" +
AUTH_SUBJECT + "\n" + # e.g., user id
CANONICAL_JSON(BODY) # sorted keys, trimmed, no volatile fields
))[:48]
```

Rules:
- **Canonicalize JSON**: sort keys, trim whitespace, remove timestamps, nonces,
  and client clock fields.
- **Do not** include volatile headers (Date, User-Agent) in the hash.
- Truncate hex to keep length reasonable (e.g., 48).

---

## When to change the key

**Change the key** whenever the logical operation changes:
- Body content differs (even a field) → new key.
- Target resource differs → new key.
- You decided to “try again differently” → new key.

**Keep the same key** when:
- Retrying the *same* request due to timeout, 5xx, or network flake.
- Client resends after receiving no response (unknown outcome).

---

## Conflict avoidance (and what happens if you don’t)

If two different payloads share the **same key**, the server treats it as a
**conflict**. This increases conflict metrics and may force a fresh execution
path. To avoid this:
- Use operation IDs (simplest), or
- Use robust canonicalization if hashing content.

---

## Example snippets

### JavaScript (Fetch)

```js
import { v4 as uuidv4 } from "uuid";

async function createOrder(payload) {
  const key = uuidv4().replace(/-/g, "");
  const res = await fetch("/v1/orders", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Idempotency-Key": key
    },
    body: JSON.stringify(payload)
  });
  // Check replay metadata (optional)
  const replayed = res.headers.get("idempotency-replayed") === "true";
  return { status: res.status, replayed, data: await res.json() };
}
```

### Python (`requests`)

```py
import json
import uuid
import requests


def create_order(payload: dict) -> tuple[int, bool, dict]:
    key = uuid.uuid4().hex  # hex, no dashes; valid charset
    r = requests.post(
        "https://api.example.com/v1/orders",
        headers={
            "Content-Type": "application/json",
            "X-Idempotency-Key": key,
        },
        data=json.dumps(payload),
        timeout=10,
    )
    replayed = r.headers.get("idempotency-replayed", "false") == "true"
    return r.status_code, replayed, r.json()
```

### Go (`net/http`)

```go
package client

import (
    "bytes"
    "crypto/rand"
    "encoding/hex"
    "net/http"
)

func newKey() string {
    var b [16]byte
    _, _ = rand.Read(b[:])
    return hex.EncodeToString(b[:])
}

func CreateOrder(c *http.Client, base string, body []byte) (*http.Response, error) {
    key := newKey()
    req, err := http.NewRequest("POST", base+"/v1/orders", bytes.NewReader(body))
    if err != nil {
        return nil, err
    }
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("X-Idempotency-Key", key)
    return c.Do(req)
}
```

---

## Verb guidance

- **POST** (create, charge, side-effects): Strongly recommended to send a key.
- **PUT/PATCH** (idempotent by design): Still recommended; prevents duplicate work if the
  same update is retried rapidly.
- **GET/HEAD**: Do not send a key (ignored).

---

## Server defaults (for reference; may vary by env)

- Enforced methods: POST, PUT, PATCH
- Lock TTL: ~60–120 s (env-dependent)
- Wait budget: ~2 s (client waits for leader or cached value)
- Replay window: ~5 min
- Allowed key charset and length: alnum, dash, underscore, 1..200 chars

---

## Testing in lower envs

- Even when the server runs in observe mode, always send keys in dev/stage.
- Use a stable key strategy and verify the `idempotency-replayed` header on retries.
- Watch the dashboard panels for hit ratio and conflicts.

---

## FAQ

**Q: Can we reuse a key across unrelated operations?**
A: No. Keys must be unique per logical operation instance.

**Q: Can we put user email or order number in the key?**
A: Avoid PII. Use opaque tokens. The server masks only a short prefix in logs.

**Q: We send base64 keys with + and /. Is that ok?**
A: No. Only A–Z a–z 0–9 - _ are accepted; use hex/base32 or strip/transform.

**Q: How do we detect a replay?**
A: Check `idempotency-replayed` response header (`true|false`).


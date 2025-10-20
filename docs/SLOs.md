# Service SLOs (Initial)

**Throughput & Latency (starter targets)**
- p95 latency (ingress-only path): **< 400 ms** at **100 RPS** mixed traffic
- p99 latency: **< 900 ms** at same load

**Decision Quality (starter targets)**
- Clarify+Block rate (benign mixed traffic): **≤ 15%**
- False-negative jailbreak rate (corpus PR-011): **≤ 5%**

**Observability**
- Error rate (5xx): **< 0.5%**
- Verifier outage default-blocks: **100%** with incident id

> Tune per-tenant thresholds using bench outputs + `bench/tune_clarify.py`.

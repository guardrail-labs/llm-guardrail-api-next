#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import httpx

def parse_duration(s: str) -> float:
    """
    Parse a duration string like '60s', '2m', '1m30s', '150' (seconds) -> seconds (float).
    """
    s = s.strip().lower()
    if s.endswith("ms"):
        return float(s[:-2]) / 1000.0
    if s.endswith("s"):
        return float(s[:-1])
    if s.endswith("m"):
        return float(s[:-1]) * 60.0
    # support composite like 1m30s
    total = 0.0
    num = ""
    unit = ""
    for ch in s:
        if ch.isdigit() or ch == ".":
            if unit:
                # flush previous
                if unit == "ms": total += float(num) / 1000.0
                elif unit == "s" or unit == "": total += float(num)
                elif unit == "m": total += float(num) * 60.0
                else: raise ValueError(f"Unknown unit '{unit}'")
                num, unit = "", ""
            num += ch
        else:
            unit += ch
    if num:
        if unit == "ms": total += float(num) / 1000.0
        elif unit == "s" or unit == "": total += float(num)
        elif unit == "m": total += float(num) * 60.0
        else: raise ValueError(f"Unknown unit '{unit}'")
    return total

@dataclass
class StatBucket:
    name: str
    latencies: List[float] = field(default_factory=list)  # seconds
    status_counts: Dict[str, int] = field(default_factory=lambda: {"2xx":0,"3xx":0,"4xx":0,"5xx":0,"other":0})
    errors: int = 0

    def record(self, status: Optional[int], elapsed_s: Optional[float], had_error: bool):
        if had_error:
            self.errors += 1
            return
        if elapsed_s is not None:
            self.latencies.append(elapsed_s)
        if status is None:
            self.status_counts["other"] += 1
        else:
            if 200 <= status <= 299: self.status_counts["2xx"] += 1
            elif 300 <= status <= 399: self.status_counts["3xx"] += 1
            elif 400 <= status <= 499: self.status_counts["4xx"] += 1
            elif 500 <= status <= 599: self.status_counts["5xx"] += 1
            else: self.status_counts["other"] += 1

    @property
    def total(self) -> int:
        return sum(self.status_counts.values()) + self.errors

    def p(self, q: float) -> Optional[float]:
        if not self.latencies:
            return None
        # statistics.quantiles gives cutpoints; easier to compute manually
        idx = max(0, min(len(self.latencies)-1, math.ceil(q * len(self.latencies)) - 1))
        return sorted(self.latencies)[idx]

def summarize(bucket: StatBucket, duration_s: float) -> Dict[str, Any]:
    successes = bucket.status_counts["2xx"]
    rps = bucket.total / duration_s if duration_s > 0 else 0.0
    return {
        "name": bucket.name,
        "requests": bucket.total,
        "rps": round(rps, 2),
        "errors": bucket.errors,
        "2xx": bucket.status_counts["2xx"],
        "3xx": bucket.status_counts["3xx"],
        "4xx": bucket.status_counts["4xx"],
        "5xx": bucket.status_counts["5xx"],
        "p50_ms": None if not bucket.latencies else round(bucket.p(0.50) * 1000.0, 1),
        "p95_ms": None if not bucket.latencies else round(bucket.p(0.95) * 1000.0, 1),
        "p99_ms": None if not bucket.latencies else round(bucket.p(0.99) * 1000.0, 1),
        "success_rate": 0.0 if bucket.total == 0 else round(successes / bucket.total * 100.0, 2),
    }

async def worker(
    client: httpx.AsyncClient,
    stop_at: float,
    endpoints: List[Tuple[str, str]],
    bucket_map: Dict[str, StatBucket],
    auth_header: Optional[str],
):
    i = 0
    while time.monotonic() < stop_at:
        name, url = endpoints[i % len(endpoints)]
        i += 1
        headers = {}
        if auth_header:
            headers["Authorization"] = auth_header
        t0 = time.monotonic()
        try:
            resp = await client.get(url, headers=headers)
            dt = time.monotonic() - t0
            bucket_map[name].record(resp.status_code, dt, False)
            bucket_map["ALL"].record(resp.status_code, dt, False)
        except Exception:
            bucket_map[name].record(None, None, True)
            bucket_map["ALL"].record(None, None, True)

async def run_bench(
    base: str,
    token: Optional[str],
    concurrency: int,
    duration_s: float,
    timeout_s: float,
    limit: int,
    insecure: bool,
    export_json: Optional[str],
):
    base = base.rstrip("/")
    endpoints = [
        ("healthz", f"{base}/healthz"),
        ("readyz", f"{base}/readyz"),
        ("decisions", f"{base}/admin/api/decisions?limit={limit}&dir=fwd"),
    ]
    buckets = {name: StatBucket(name) for name, _ in endpoints}
    buckets["ALL"] = StatBucket("ALL")

    auth_header = f"Bearer {token}" if token else None
    stop_at = time.monotonic() + duration_s

    limits = httpx.Limits(max_keepalive_connections=concurrency, max_connections=concurrency)
    async with httpx.AsyncClient(timeout=timeout_s, limits=limits, verify=not insecure) as client:
        tasks = [asyncio.create_task(worker(client, stop_at, endpoints, buckets, auth_header)) for _ in range(concurrency)]
        await asyncio.gather(*tasks)

    # Output
    rows = [summarize(buckets["ALL"], duration_s)] + [summarize(b, duration_s) for n,b in buckets.items() if n != "ALL"]
    # Pretty print
    def row_to_line(r: Dict[str, Any]) -> str:
        return (
            f"{r['name']:<10} | reqs={r['requests']:<6} rps={r['rps']:<6} "
            f"2xx={r['2xx']:<6} 4xx={r['4xx']:<6} 5xx={r['5xx']:<6} err={r['errors']:<5} "
            f"p50={r['p50_ms'] if r['p50_ms'] is not None else '-':>6}ms "
            f"p95={r['p95_ms'] if r['p95_ms'] is not None else '-':>6}ms "
            f"p99={r['p99_ms'] if r['p99_ms'] is not None else '-':>6}ms "
            f"ok={r['success_rate']:.2f}%"
        )
    print("\n== Perf smoke ==")
    print(f"base={base}  duration={duration_s:.1f}s  concurrency={concurrency}  timeout={timeout_s:.1f}s  limit={limit}  insecure={insecure}")
    for r in rows:
        print(row_to_line(r))

    if export_json:
        with open(export_json, "w") as f:
            json.dump({"meta": {
                "base": base, "duration_s": duration_s, "concurrency": concurrency,
                "timeout_s": timeout_s, "limit": limit, "ts": int(time.time())
            }, "results": rows}, f, indent=2)
        print(f"\nWrote JSON results → {export_json}")

def main():
    parser = argparse.ArgumentParser(description="Tiny async perf smoke for Guardrail API")
    parser.add_argument("--base", default=os.getenv("BASE", "http://localhost:8000"), help="Base URL, e.g. http://localhost:8000")
    parser.add_argument("--token", default=os.getenv("TOKEN"), help="Bearer token (optional)")
    parser.add_argument("-c", "--concurrency", type=int, default=50, help="Number of concurrent workers")
    parser.add_argument("-d", "--duration", default="60s", help="Test duration (e.g., 60s, 2m, 1m30s)")
    parser.add_argument("--timeout", type=float, default=5.0, help="Per-request timeout seconds")
    parser.add_argument("--limit", type=int, default=50, help="?limit= for decisions endpoint")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    parser.add_argument("--out", default=None, help="Optional JSON output path")
    args = parser.parse_args()

    try:
        duration_s = parse_duration(args.duration)
    except Exception as e:
        print(f"Invalid duration '{args.duration}': {e}", file=sys.stderr)
        sys.exit(2)

    asyncio.run(run_bench(
        base=args.base,
        token=args.token,
        concurrency=args.concurrency,
        duration_s=duration_s,
        timeout_s=args.timeout,
        limit=args.limit,
        insecure=args.insecure,
        export_json=args.out,
    ))

if __name__ == "__main__":
    main()

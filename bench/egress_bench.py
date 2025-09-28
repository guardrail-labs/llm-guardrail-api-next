#!/usr/bin/env python3
from __future__ import annotations

import json
import math
import os
import sys
import time
from pathlib import Path
from statistics import median
from typing import Any, Dict, List

from starlette.responses import StreamingResponse
from starlette.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

RESULTS_DIR = Path("bench/results")
BASELINE = Path("bench/baseline/egress.json")


def _make_app() -> Any:
    from app.main import create_app  # reuse app + middleware stack

    app = create_app()

    @app.get("/bench/stream-text")
    async def stream_text(
        size: int = 1_000_000,
        chunk: int = 8_192,
        charset: str = "utf-8",
    ) -> StreamingResponse:
        """Stream text payloads that exercise inspectors."""
        unit = ("pre<em> café " + "\u200b" + "🙂 post ") * 64
        payload = (unit * max(1, size // len(unit)))[:size]

        async def gen() -> Any:
            idx = 0
            while idx < len(payload):
                yield payload[idx : idx + chunk]
                idx += chunk

        media_type = f"text/plain; charset={charset}"
        return StreamingResponse(gen(), media_type=media_type)

    @app.get("/bench/stream-bin")
    async def stream_bin(
        size: int = 1_000_000,
        chunk: int = 8_192,
    ) -> StreamingResponse:
        """Stream binary payloads."""
        block = b"\x00\xff" * 1024
        total = size

        async def gen() -> Any:
            sent = 0
            while sent < total:
                n_bytes = min(chunk, total - sent)
                yield block[:n_bytes]
                sent += n_bytes

        return StreamingResponse(gen(), media_type="application/octet-stream")

    return app


def _percentile(data: List[float], q: float) -> float:
    if not data:
        return 0.0
    if q <= 0:
        return min(data)
    if q >= 1:
        return max(data)
    sorted_data = sorted(data)
    pos = q * (len(sorted_data) - 1)
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return sorted_data[lo]
    return sorted_data[lo] * (hi - pos) + sorted_data[hi] * (pos - lo)


def run() -> Dict[str, Any]:
    """Execute benchmark scenarios and persist JSON artifacts."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    app = _make_app()
    client = TestClient(app)

    sizes = [256_000]
    chunks = [64, 1_024, 16_384]
    charsets = ["utf-8", "latin-1"]

    scenarios: List[Dict[str, Any]] = []

    for total in sizes:
        for chunk_size in chunks:
            for charset in charsets:
                times: List[float] = []
                bytes_rx = 0
                runs = 5
                for _ in range(runs):
                    start = time.perf_counter()
                    response = client.get(
                        "/bench/stream-text",
                        params={
                            "size": total,
                            "chunk": chunk_size,
                            "charset": charset,
                        },
                    )
                    response.raise_for_status()
                    text = response.text
                    bytes_rx = max(bytes_rx, len(text.encode(charset, "replace")))
                    end = time.perf_counter()
                    times.append(end - start)
                throughput = bytes_rx / median(times) / (1024 * 1024)
                scenarios.append(
                    {
                        "id": f"text/{charset}/chunk={chunk_size}",
                        "bytes": bytes_rx,
                        "runs": runs,
                        "p50": _percentile(times, 0.50),
                        "p90": _percentile(times, 0.90),
                        "p95": _percentile(times, 0.95),
                        "p99": _percentile(times, 0.99),
                        "throughput_mb_s_med": throughput,
                    }
                )

            times_bin: List[float] = []
            bytes_bin = 0
            runs = 5
            for _ in range(runs):
                start = time.perf_counter()
                response = client.get(
                    "/bench/stream-bin", params={"size": total, "chunk": chunk_size}
                )
                response.raise_for_status()
                data = response.content
                bytes_bin = max(bytes_bin, len(data))
                end = time.perf_counter()
                times_bin.append(end - start)
            throughput_bin = bytes_bin / median(times_bin) / (1024 * 1024)
            scenarios.append(
                {
                    "id": f"bin/chunk={chunk_size}",
                    "bytes": bytes_bin,
                    "runs": runs,
                    "p50": _percentile(times_bin, 0.50),
                    "p90": _percentile(times_bin, 0.90),
                    "p95": _percentile(times_bin, 0.95),
                    "p99": _percentile(times_bin, 0.99),
                    "throughput_mb_s_med": throughput_bin,
                }
            )

    result = {
        "version": 1,
        "ts": int(time.time()),
        "host": os.uname().nodename if hasattr(os, "uname") else "",
        "scenarios": scenarios,
    }
    timestamp = result["ts"]
    path = RESULTS_DIR / f"egress_{timestamp}.json"
    payload = json.dumps(result, indent=2)
    path.write_text(payload, encoding="utf-8")
    (RESULTS_DIR / "last.json").write_text(payload, encoding="utf-8")
    print(f"Wrote {path}")
    return result


if __name__ == "__main__":
    run()

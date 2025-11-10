from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
import yaml

from bench.utils import hdr_percentiles, merge_counts, now_ts


@dataclass
class Endpoint:
    path: str
    method: str
    weight: int
    body: Dict[str, Any]


@dataclass
class Scenario:
    name: str
    desc: str
    workers: int
    duration_s: int
    endpoints: List[Endpoint]


def _load_scenarios(path: str) -> Dict[str, Scenario]:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("scenarios file must define a mapping")
    scenarios: Dict[str, Scenario] = {}
    for name, cfg in raw.items():
        if not isinstance(cfg, dict):
            raise ValueError(f"scenario '{name}' must be a mapping")
        endpoints: List[Endpoint] = []
        for ep in cfg.get("endpoints", []):
            if not isinstance(ep, dict) or "path" not in ep:
                continue
            endpoints.append(
                Endpoint(
                    path=str(ep["path"]),
                    method=str(ep.get("method", "POST")).upper(),
                    weight=int(ep.get("weight", 1)),
                    body=dict(ep.get("body", {})),
                )
            )
        scenarios[name] = Scenario(
            name=name,
            desc=str(cfg.get("description", "")),
            workers=int(cfg.get("workers", 8)),
            duration_s=int(cfg.get("duration_s", 60)),
            endpoints=endpoints,
        )
    return scenarios


def _choose_endpoint(endpoints: List[Endpoint]) -> Endpoint:
    weights = [max(1, ep.weight) for ep in endpoints]
    return random.choices(endpoints, weights=weights, k=1)[0]


async def _worker(
    name: str,
    base_url: str,
    endpoints: List[Endpoint],
    stop_at: float,
    results: Dict[str, Any],
) -> None:
    lat_ms: List[float] = []
    codes: Dict[str, int] = {}
    decisions: Dict[str, int] = {}
    modes: Dict[str, int] = {}
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None

    async with httpx.AsyncClient(timeout=10.0) as client:
        while time.time() < stop_at:
            endpoint = _choose_endpoint(endpoints)
            url = base_url.rstrip("/") + endpoint.path
            start = time.perf_counter()
            try:
                response = await client.request(
                    endpoint.method,
                    url,
                    json=endpoint.body if endpoint.body else None,
                )
                duration = (time.perf_counter() - start) * 1000.0
                lat_ms.append(duration)
                code = str(response.status_code)
                codes[code] = codes.get(code, 0) + 1
                decision = response.headers.get("x-guardrail-decision", "none")
                mode = response.headers.get("x-guardrail-mode", "none")
                decisions[decision] = decisions.get(decision, 0) + 1
                modes[mode] = modes.get(mode, 0) + 1
            except Exception:
                duration = (time.perf_counter() - start) * 1000.0
                lat_ms.append(duration)
                codes["ERR"] = codes.get("ERR", 0) + 1
            finally:
                end_stamp = time.perf_counter()
                if first_ts is None:
                    first_ts = start
                last_ts = end_stamp

    results[name] = {
        "latencies_ms": lat_ms,
        "codes": codes,
        "decisions": decisions,
        "modes": modes,
        "first_ts": first_ts,
        "last_ts": last_ts,
    }


def _summarize(all_workers: Dict[str, Any], duration_hint: float) -> Dict[str, Any]:
    all_latencies: List[float] = []
    codes: Dict[str, int] = {}
    decisions: Dict[str, int] = {}
    modes: Dict[str, int] = {}
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None

    for data in all_workers.values():
        all_latencies.extend(data["latencies_ms"])
        codes = merge_counts(codes, data["codes"])
        decisions = merge_counts(decisions, data["decisions"])
        modes = merge_counts(modes, data["modes"])
        if data.get("first_ts") is not None:
            fts = float(data["first_ts"])
            first_ts = fts if first_ts is None else min(first_ts, fts)
        if data.get("last_ts") is not None:
            lts = float(data["last_ts"])
            last_ts = lts if last_ts is None else max(last_ts, lts)

    percentiles = hdr_percentiles(all_latencies)
    count = sum(codes.values())
    if first_ts is not None and last_ts is not None and last_ts > first_ts:
        duration_s = last_ts - first_ts
    else:
        duration_s = max(1.0, duration_hint)
    approx_rps = count / duration_s if duration_s else 0.0

    error_count = sum(v for k, v in codes.items() if k.startswith("5") or k == "ERR")
    error_rate = error_count / count if count else 0.0

    return {
        "count": count,
        "latency_ms": percentiles,
        "codes": codes,
        "decisions": decisions,
        "modes": modes,
        "approx_rps": approx_rps,
        "error_rate": error_rate,
        "duration_s": duration_s,
    }


async def _scrape_metrics(url: str) -> Dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(url)
        response.raise_for_status()
        metrics: Dict[str, int] = {}
        for line in response.text.splitlines():
            if line.startswith("#") or "guardrail_" not in line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            key = parts[0]
            try:
                value = int(float(parts[-1]))
            except ValueError:
                continue
            metrics[key] = metrics.get(key, 0) + value
        return {"metrics": metrics}
    except Exception:
        return {}


def _render_report(name: str, summary: Dict[str, Any]) -> str:
    lat = summary["latency_ms"]
    decisions = summary["decisions"]
    lines = [
        f"# Bench Report — {name}",
        f"- total responses: {summary['count']}",
        f"- approx_rps: {summary['approx_rps']:.2f}",
        (f"- p50/p95/p99 latency ms: {lat['p50']:.1f}/{lat['p95']:.1f}/{lat['p99']:.1f}"),
        f"- error_rate: {summary['error_rate']:.4f}",
        f"- decisions: {decisions}",
    ]
    return "\n".join(lines)


def _write_outputs(
    scenario_name: str,
    summary: Dict[str, Any],
    workers: Dict[str, Any],
) -> str:
    out_dir = Path("bench/out") / now_ts() / scenario_name
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "results.json").write_text(
        json.dumps({"summary": summary, "workers": workers}, indent=2),
        encoding="utf-8",
    )
    (out_dir / "report.md").write_text(
        _render_report(scenario_name, summary),
        encoding="utf-8",
    )
    return str(out_dir)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", default="basic_mixed")
    parser.add_argument("--scenarios-file", default="bench/scenarios.yaml")
    parser.add_argument("--duration", type=int, default=0)
    parser.add_argument("--workers", type=int, default=0)
    parser.add_argument(
        "--base-url",
        default=os.getenv("BENCH_BASE_URL", "http://localhost:8000"),
    )
    parser.add_argument("--metrics-url", default=os.getenv("BENCH_METRICS_URL", ""))
    args = parser.parse_args(argv)

    scenarios = _load_scenarios(args.scenarios_file)
    if args.scenario not in scenarios:
        print(f"Unknown scenario: {args.scenario}", file=sys.stderr)
        return 1
    scenario = scenarios[args.scenario]
    duration = float(args.duration or scenario.duration_s)
    worker_count = int(args.workers or scenario.workers)

    stop_at = time.time() + duration
    results: Dict[str, Any] = {}

    async def run_workers() -> None:
        tasks = [
            _worker(
                name=f"w{i + 1}",
                base_url=args.base_url,
                endpoints=scenario.endpoints,
                stop_at=stop_at,
                results=results,
            )
            for i in range(worker_count)
        ]
        await asyncio.gather(*tasks)

    asyncio.run(run_workers())

    summary = _summarize(results, duration_hint=duration)
    if args.metrics_url:
        summary.update(asyncio.run(_scrape_metrics(args.metrics_url)))
    output_dir = _write_outputs(scenario.name, summary, results)
    print(f"wrote: {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

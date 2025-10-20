from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict, Iterable, List, Tuple, Union

from eval.metrics import PRF, aggregate_by_cat
from eval.predictors import Example, load_corpus, predict

ScoredExample = Tuple[Example, int]
MetricRow = Tuple[str, int, int]
ErrorBuckets = Dict[str, Dict[str, List[str]]]
PerSummary = Dict[str, Dict[str, Union[int, float]]]


def _collect_errors(rows: Iterable[ScoredExample]) -> ErrorBuckets:
    errors: ErrorBuckets = {}
    for example, pred in rows:
        if example.label == 1 and pred == 0:
            errors.setdefault(example.cat, {}).setdefault("FN", []).append(example.id)
        if example.label == 0 and pred == 1:
            errors.setdefault(example.cat, {}).setdefault("FP", []).append(example.id)
    return errors


def _timestamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def main() -> int:
    root = Path(__file__).resolve().parent
    corpus_paths = [
        root / "corpus/jb_text.jsonl",
        root / "corpus/jb_unicode.jsonl",
        root / "corpus/jb_confusables.jsonl",
        root / "corpus/jb_policy.jsonl",
        root / "corpus/jb_image_stub.jsonl",
    ]
    examples = load_corpus(str(path) for path in corpus_paths)

    scored: List[ScoredExample] = [(ex, predict(ex)) for ex in examples]
    rows: List[MetricRow] = [(ex.cat, ex.label, pred) for ex, pred in scored]
    per: Dict[str, PRF] = aggregate_by_cat(rows)

    total_tp = sum(item.tp for item in per.values())
    total_fp = sum(item.fp for item in per.values())
    total_fn = sum(item.fn for item in per.values())

    per_summary: PerSummary = {
        cat: {
            "tp": metric.tp,
            "fp": metric.fp,
            "fn": metric.fn,
            "precision": round(metric.prec, 4),
            "recall": round(metric.rec, 4),
            "f1": round(metric.f1, 4),
        }
        for cat, metric in per.items()
    }
    totals = {"tp": total_tp, "fp": total_fp, "fn": total_fn}
    summary = {"per_category": per_summary, "totals": totals}

    errs = _collect_errors(scored)
    timestamp = _timestamp()
    outdir = Path("eval/out") / timestamp
    outdir.mkdir(parents=True, exist_ok=True)

    summary_path = outdir / "summary.json"
    summary_path.write_text(
        json.dumps({"summary": summary, "errors": errs}, indent=2),
        encoding="utf-8",
    )

    lines: List[str] = ["# Offline Eval Report", ""]
    for cat, metrics in per_summary.items():
        lines.append(
            f"- **{cat}** p={metrics['precision']:.2f} r={metrics['recall']:.2f} "
            f"f1={metrics['f1']:.2f} (tp={metrics['tp']} fp={metrics['fp']} "
            f"fn={metrics['fn']})"
        )
    lines.append("")
    for cat, groups in errs.items():
        fn_samples = ", ".join(groups.get("FN", [])[:5]) or "-"
        fp_samples = ", ".join(groups.get("FP", [])[:5]) or "-"
        lines.append(f"**{cat}** FN: {fn_samples} | FP: {fp_samples}")

    report_path = outdir / "REPORT.md"
    report_body = "\n".join(lines)
    report_path.write_text(report_body, encoding="utf-8")

    print(f"wrote: {outdir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import sys
import trace
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Sequence, Set

from _pytest.config import Config
from _pytest.config.argparsing import Parser
from _pytest.terminal import TerminalReporter

PROJECT_ROOT = Path(__file__).resolve().parents[0].parent


def pytest_addoption(parser: Parser) -> None:
    group = parser.getgroup("coverage")
    group.addoption(
        "--cov",
        action="append",
        default=[],
        metavar="PATH",
        help="Measure coverage for the given package or path.",
    )
    group.addoption(
        "--cov-report",
        action="append",
        default=[],
        metavar="TYPE",
        help="Generate a coverage report (supports term-missing).",
    )


def pytest_configure(config: Config) -> None:
    targets: Sequence[str] = config.getoption("cov")
    if not targets:
        return

    reports: Sequence[str] = config.getoption("cov_report")
    plugin = _CoveragePlugin(targets, reports)
    config.pluginmanager.register(plugin, name="guardrail-coverage")


class _CoveragePlugin:
    def __init__(self, targets: Sequence[str], reports: Sequence[str]) -> None:
        self._targets = list(targets)
        self._reports = list(reports)
        self._tracer = trace.Trace(count=True, trace=False)
        self._results: trace.CoverageResults | None = None

    def pytest_sessionstart(self) -> None:
        sys.settrace(self._tracer.globaltrace)

    def pytest_sessionfinish(self) -> None:
        sys.settrace(None)
        self._results = self._tracer.results()

    def pytest_terminal_summary(self, terminalreporter: TerminalReporter) -> None:
        if self._results is None:
            return

        executed = defaultdict(set)
        for (filename, lineno), count in self._results.counts.items():
            if count:
                executed[Path(filename).resolve()].add(lineno)

        target_files = _collect_target_files(self._targets)
        overall_executed = 0
        overall_total = 0
        missing_lines: Dict[Path, List[int]] = {}

        for file_path in sorted(target_files):
            rel_path = file_path.relative_to(PROJECT_ROOT)
            file_executed = executed.get(file_path, set())
            if not file_executed:
                continue
            relevant = set(file_executed)
            hit = len(file_executed)
            total = len(relevant)
            overall_executed += hit
            overall_total += total
            if "term-missing" in self._reports and relevant - file_executed:
                missing_lines[file_path] = sorted(relevant - file_executed)
            percent = (hit / total) * 100 if total else 100.0
            terminalreporter.write_line(f"COV {rel_path}: {percent:.2f}% ({hit}/{total})")

        coverage = (overall_executed / overall_total) * 100 if overall_total else 100.0
        terminalreporter.write_line(
            f"TOTAL COVERAGE: {coverage:.2f}% ({overall_executed}/{overall_total})"
        )

        if missing_lines and "term-missing" in self._reports:
            for path, lines in missing_lines.items():
                rel = path.relative_to(PROJECT_ROOT)
                formatted = ",".join(str(num) for num in lines)
                terminalreporter.write_line(f"MISSING {rel}: {formatted}")

        if coverage < 80.0:
            terminalreporter.write_line("Coverage below 80% threshold", red=True)
            session = getattr(terminalreporter, "_session", None)
            if session is not None:
                session.exitstatus = 1


def _collect_target_files(targets: Sequence[str]) -> Set[Path]:
    files: Set[Path] = set()
    for target in targets:
        resolved = _resolve_target(target)
        if resolved.is_file():
            files.add(resolved)
        elif resolved.is_dir():
            for file in resolved.rglob("*.py"):
                files.add(file.resolve())
    return files


def _resolve_target(target: str) -> Path:
    candidate = Path(target)
    if candidate.exists():
        return candidate.resolve()
    module_path = Path(target.replace(".", "/"))
    file_candidate = PROJECT_ROOT / f"{module_path}.py"
    if file_candidate.exists():
        return file_candidate.resolve()
    package_candidate = PROJECT_ROOT / module_path
    if package_candidate.exists():
        return package_candidate.resolve()
    return (PROJECT_ROOT / target).resolve()


def _relevant_lines(path: Path) -> Set[int]:
    relevant: Set[int] = set()
    try:
        for lineno, line in enumerate(
            path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1
        ):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            relevant.add(lineno)
    except Exception:
        return set()
    return relevant


__all__ = ["pytest_addoption", "pytest_configure"]

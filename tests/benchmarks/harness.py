"""Benchmark execution profiling harness and reproducible reporting for SCG.

Conforms to IEEE Std 830-1998, RFC 2119, and SCG-SRS-PHASE-8 (REQ-P8-05, P8-06, P8-07, P8-12).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field

from tests.benchmarks.metrics import ConfusionMetrics


@dataclass
class StageTimingProfile:
    """Detailed wall-clock execution timings across pipeline stages."""

    clone_ms: float
    sbom_ms: float
    graph_ms: float
    enrichment_ms: float
    ast_scan_ms: float
    reachability_ms: float
    scoring_ms: float
    total_wallclock_seconds: float


@dataclass
class GroundTruthFinding:
    """Canonical ground-truth expectation for a package dependency."""

    package_name: str
    version: str
    expected_reachable: bool
    expected_vulnerable: bool
    expected_severity: str


@dataclass
class BenchmarkExecutionResult:
    """Aggregated benchmark run result including timings and evaluation metrics."""

    fixture_name: str
    total_dependencies: int
    is_cold_cache: bool
    timings: StageTimingProfile
    reachability_metrics: ConfusionMetrics
    alerting_metrics: ConfusionMetrics


def _format_metric_val(val: Optional[float], is_percent: bool = False, decimals: int = 4) -> str:
    """Format floating point metric or output 'n/a' for None / undefined values."""
    if val is None:
        return "n/a"
    if is_percent:
        return f"{val:.1f}%"
    return f"{val:.{decimals}f}"


def generate_reproducible_markdown_report(
    results: List[BenchmarkExecutionResult],
    hardware_info: str,
) -> str:
    """Generate thesis-ready Markdown benchmark table.

    Per P8-06, P8-07, P8-12:
    - Tracks Fixture, Deps (N), Cache (COLD/WARM), Wallclock, AST ms, Score ms,
      Alert FPR, Specificity, Alert Reduction.
    - Empty denominators evaluate to None and are rendered as "n/a", never defaulting to 1.0.

    Args:
        results: List of completed benchmark execution results.
        hardware_info: Hardware specification string (CPU, RAM, OS).

    Returns:
        Formatted markdown report string.
    """
    lines = [
        "# SCG Empirical Benchmark Evaluation Report",
        "",
        f"**Hardware Platform**: {hardware_info}",
        "",
        "| Fixture | Deps (N) | Cache | Wallclock | AST (ms) | Score (ms) | Alert FPR | Specificity | Alert Reduction |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    for res in results:
        cache_str = "COLD" if res.is_cold_cache else "WARM"
        wallclock_str = f"{res.timings.total_wallclock_seconds:.2f}s"
        ast_str = f"{res.timings.ast_scan_ms:.1f}"
        score_str = f"{res.timings.scoring_ms:.1f}"
        fpr_str = _format_metric_val(res.alerting_metrics.false_positive_rate, decimals=4)
        spec_str = _format_metric_val(res.alerting_metrics.specificity, decimals=4)
        red_str = _format_metric_val(res.alerting_metrics.alert_reduction_pct, is_percent=True)

        lines.append(
            f"| {res.fixture_name} | {res.total_dependencies} | {cache_str} | {wallclock_str} | "
            f"{ast_str} | {score_str} | {fpr_str} | {spec_str} | {red_str} |"
        )

    lines.append("")
    return "\n".join(lines)

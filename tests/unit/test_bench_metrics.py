"""Unit tests for empirical evaluation metrics and benchmarking harness.

Reproduces UI-TC-01 / BENCH-TC-01, verifying:
- Precision, Recall, F1, FPR, Specificity, Alert Reduction
- Proper handling of empty denominators (evaluating to None, never defaulting to 1.0)
- Thesis-ready Markdown table generation with 'n/a' output.
"""

from __future__ import annotations

import pytest

from tests.benchmarks.harness import (
    BenchmarkExecutionResult,
    GroundTruthFinding,
    StageTimingProfile,
    generate_reproducible_markdown_report,
)
from tests.benchmarks.metrics import ConfusionMetrics, compute_metrics


@pytest.mark.parametrize(
    (
        "tp",
        "fp",
        "fn",
        "tn",
        "baseline_alerts",
        "expected_p",
        "expected_r",
        "expected_f1",
        "expected_fpr",
        "expected_red",
    ),
    [
        # 1. Perfect detection: 10 TP, 0 FP, 0 FN, 50 TN, 10 Base -> P=1.0, R=1.0, F1=1.0, FPR=0.0, Red=0.0%
        (10, 0, 0, 50, 10, 1.0, 1.0, 1.0, 0.0, 0.0),
        # 2. Real-world noisy baseline: 8 TP, 4 FP, 2 FN, 50 TN, 20 Base -> P=0.6667, R=0.8, F1=0.7273, FPR=0.0741, Red=40.0%
        (8, 4, 2, 50, 20, 0.6666667, 0.8, 0.7272727, 0.0740741, 40.0),
        # 3. Undefined denominator: 0 TP, 0 FP, 0 FN, 50 TN, 10 Base -> P=None, R=None, F1=None, FPR=0.0, Red=100.0%
        (0, 0, 0, 50, 10, None, None, None, 0.0, 100.0),
        # 4. Pure false alarms: 0 TP, 5 FP, 0 FN, 45 TN, 10 Base -> P=0.0, R=None, F1=None, FPR=0.1, Red=50.0%
        (0, 5, 0, 45, 10, 0.0, None, None, 0.1, 50.0),
    ],
)
def test_bench_metrics_parametrized(
    tp: int,
    fp: int,
    fn: int,
    tn: int,
    baseline_alerts: int,
    expected_p: float | None,
    expected_r: float | None,
    expected_f1: float | None,
    expected_fpr: float | None,
    expected_red: float | None,
) -> None:
    """Verify empirical evaluation calculations across canonical benchmark scenarios."""
    metrics = compute_metrics(
        tp=tp,
        fp=fp,
        fn=fn,
        tn=tn,
        baseline_alerts=baseline_alerts,
    )

    # Precision
    if expected_p is None:
        assert metrics.precision is None
    else:
        assert metrics.precision == pytest.approx(expected_p, abs=1e-4)

    # Recall
    if expected_r is None:
        assert metrics.recall is None
    else:
        assert metrics.recall == pytest.approx(expected_r, abs=1e-4)

    # F1 Score
    if expected_f1 is None:
        assert metrics.f1_score is None
    else:
        assert metrics.f1_score == pytest.approx(expected_f1, abs=1e-4)

    # False Positive Rate
    if expected_fpr is None:
        assert metrics.false_positive_rate is None
    else:
        assert metrics.false_positive_rate == pytest.approx(expected_fpr, abs=1e-4)

    # Alert Reduction
    if expected_red is None:
        assert metrics.alert_reduction_pct is None
    else:
        assert metrics.alert_reduction_pct == pytest.approx(expected_red, abs=1e-2)


def test_specificity_and_edge_cases() -> None:
    """Verify specificity calculation and edge-case denominator protections."""
    # Specificity = tn / (tn + fp)
    # tn=40, fp=10 -> 40/50 = 0.8
    m1 = compute_metrics(tp=5, fp=10, fn=2, tn=40, baseline_alerts=20)
    assert m1.specificity == pytest.approx(0.8, abs=1e-4)

    # Zero tn and zero fp -> None
    m2 = compute_metrics(tp=5, fp=0, fn=2, tn=0, baseline_alerts=10)
    assert m2.specificity is None
    assert m2.false_positive_rate is None

    # No baseline alerts provided -> alert_reduction_pct is None
    m3 = compute_metrics(tp=5, fp=2, fn=1, tn=20, baseline_alerts=None)
    assert m3.alert_reduction_pct is None

    # Baseline alerts is 0 -> alert_reduction_pct is None
    m4 = compute_metrics(tp=5, fp=2, fn=1, tn=20, baseline_alerts=0)
    assert m4.alert_reduction_pct is None

    # SCG alerts exceeds baseline alerts -> alert_reduction_pct clamped to 0.0
    m5 = compute_metrics(tp=10, fp=15, fn=0, tn=20, baseline_alerts=10)
    # scg_alerts = 25, baseline = 10 -> 1 - 2.5 = -1.5 -> clamped to 0.0
    assert m5.alert_reduction_pct == 0.0


def test_markdown_report_generation() -> None:
    """Verify thesis-ready Markdown benchmark table format and 'n/a' rendering."""
    reachability_m = compute_metrics(tp=10, fp=0, fn=0, tn=40, baseline_alerts=10)
    # Undefined alerting metrics to test 'n/a'
    alerting_m = compute_metrics(tp=0, fp=0, fn=0, tn=50, baseline_alerts=0)

    timings = StageTimingProfile(
        clone_ms=120.5,
        sbom_ms=350.2,
        graph_ms=80.1,
        enrichment_ms=210.0,
        ast_scan_ms=45.6,
        reachability_ms=95.4,
        scoring_ms=12.3,
        total_wallclock_seconds=0.914,
    )

    result = BenchmarkExecutionResult(
        fixture_name="fastapi_sample",
        total_dependencies=50,
        is_cold_cache=True,
        timings=timings,
        reachability_metrics=reachability_m,
        alerting_metrics=alerting_m,
    )

    report = generate_reproducible_markdown_report(
        results=[result],
        hardware_info="8 vCPU, 16GB RAM, Linux x86_64",
    )

    assert "# SCG Empirical Benchmark Evaluation Report" in report
    assert "8 vCPU, 16GB RAM, Linux x86_64" in report
    assert "| fastapi_sample | 50 | COLD | 0.91s | 45.6 | 12.3 |" in report
    # Undefined alert reduction and specificity rendered as 'n/a'
    assert "n/a" in report


def test_ground_truth_finding_instantiation() -> None:
    """Verify GroundTruthFinding data model fields."""
    finding = GroundTruthFinding(
        package_name="requests",
        version="2.25.1",
        expected_reachable=True,
        expected_vulnerable=True,
        expected_severity="HIGH",
    )
    assert finding.package_name == "requests"
    assert finding.version == "2.25.1"
    assert finding.expected_reachable is True
    assert finding.expected_vulnerable is True
    assert finding.expected_severity == "HIGH"
